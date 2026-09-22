/**
 * Compile phase: turns a runtime schema into an executable plan.
 *
 * - Precomputes the accepted wire tag(s) of every node (tag dispatch).
 * - Builds per-field constraint tables (required / optional / default).
 * - Detects ambiguity statically: duplicate dispatch tags inside a SEQUENCE
 *   or SET, overlapping CHOICE alternatives, and OPTIONAL/DEFAULT fields
 *   whose tags collide with a successor.
 * - Validates DEFAULT values against their field's type at compile time, so a
 *   missing DEFAULT field can be filled without ever confusing it with an
 *   explicitly encoded value.
 */

import { ChoiceNode, Field, PrimitiveNode, SchemaNode, Tag, TagClassName } from './schema.js';
import { TagClass, UniversalTag } from './tlv.js';

export class SchemaError extends Error {
  constructor(
    message: string,
    readonly schemaPath: string,
  ) {
    super(`${message} (at ${schemaPath})`);
    this.name = 'SchemaError';
  }
}

export interface WireTag {
  tagClass: TagClass;
  tagNumber: number;
}

const tagKey = (t: WireTag): string => `${t.tagClass}:${t.tagNumber}`;

const TAG_CLASS: Record<TagClassName, TagClass> = {
  universal: TagClass.Universal,
  application: TagClass.Application,
  context: TagClass.Context,
  private: TagClass.Private,
};

const PRIMITIVE_TAG: Record<PrimitiveNode['kind'], number> = {
  boolean: UniversalTag.Boolean,
  integer: UniversalTag.Integer,
  octetString: UniversalTag.OctetString,
  bitString: UniversalTag.BitString,
  null: UniversalTag.Null,
  oid: UniversalTag.Oid,
  utf8String: UniversalTag.Utf8String,
  enum: UniversalTag.Integer,
};

const universalOf = (node: SchemaNode): number => {
  switch (node.kind) {
    case 'sequence':
    case 'sequenceOf':
      return UniversalTag.Sequence;
    case 'set':
      return UniversalTag.Set;
    case 'choice':
      throw new SchemaError('internal: choice has no universal tag', '<choice>');
    case 'ref':
      throw new SchemaError('internal: unresolved ref', node.name);
    default:
      return PRIMITIVE_TAG[node.kind];
  }
};

const tagClassOf = (tag: Tag): TagClass => TAG_CLASS[tag.class ?? 'context'];

// ---------------------------------------------------------------------------
// Plan nodes
// ---------------------------------------------------------------------------

export type Plan =
  | PrimitivePlan
  | SequencePlan
  | SetPlan
  | SequenceOfPlan
  | ChoicePlan
  | RefPlan;

interface PlanBase {
  path: string;
  /** Outermost tag on the wire, after applying explicit/implicit tagging. */
  outer: WireTag;
  /** Explicit wrapper tag when the node is explicitly tagged. */
  explicit?: WireTag;
}

export interface PrimitivePlan extends PlanBase {
  kind: PrimitiveNode['kind'];
  implicit: boolean;
}

export interface FieldPlan {
  name: string;
  required: boolean;
  hasDefault: boolean;
  defaultValue?: unknown;
  plan: Plan;
  /** Tags of this field's head TLV; a field is present iff the next TLV matches one. */
  dispatch: WireTag[];
}

export interface SequencePlan extends PlanBase {
  kind: 'sequence';
  fields: FieldPlan[];
}

export interface SetPlan extends PlanBase {
  kind: 'set';
  fields: FieldPlan[];
  byTag: Map<string, FieldPlan>;
}

export interface SequenceOfPlan extends PlanBase {
  kind: 'sequenceOf';
  element: Plan;
}

export interface ChoicePlan extends PlanBase {
  kind: 'choice';
  alternatives: Plan[];
  byTag: Map<string, Plan>;
}

export interface RefPlan extends PlanBase {
  kind: 'ref';
  name: string;
  target: () => Plan;
}

export interface CompiledSchema {
  root: Plan;
  named: Map<string, Plan>;
  /** Maximum nesting depth when decoding; guards recursive schemas. */
  maxDepth: number;
}

export interface CompileOptions {
  named?: Record<string, SchemaNode>;
  maxDepth?: number;
}

const DEFAULT_MAX_DEPTH = 64;

/** Shared state threaded through one compilation. */
interface CompileCtx {
  named: Record<string, SchemaNode>;
  namedPlans: Map<string, Plan>;
}

// ---------------------------------------------------------------------------
// Dispatch computation
// ---------------------------------------------------------------------------

/**
 * All tags a node's first TLV can carry on the wire. An untagged CHOICE
 * contributes the union of its alternatives' tags; an untagged ref
 * contributes its target's tags.
 */
const dispatchTags = (ctx: CompileCtx, node: SchemaNode, refStack: string[]): WireTag[] => {
  if (node.kind === 'choice' && !node.tag) {
    const out: WireTag[] = [];
    for (const alt of node.alternatives) out.push(...dispatchTags(ctx, alt, refStack));
    return out;
  }
  if (node.kind === 'ref' && !node.tag) {
    if (refStack.includes(node.name)) {
      // Recursive occurrence: its tags are already contributed by the first
      // occurrence of the same named type higher in the stack.
      return [];
    }
    const target = ctx.named[node.name];
    if (!target) throw new SchemaError(`unknown named type "${node.name}"`, node.name);
    return dispatchTags(ctx, target, [...refStack, node.name]);
  }
  if (node.tag) return [{ tagClass: tagClassOf(node.tag), tagNumber: node.tag.number }];
  return [{ tagClass: TagClass.Universal, tagNumber: universalOf(node) }];
};

// ---------------------------------------------------------------------------
// DEFAULT value validation (compile time)
// ---------------------------------------------------------------------------

const validateDefault = (value: unknown, node: SchemaNode, path: string): void => {
  switch (node.kind) {
    case 'boolean':
      if (typeof value !== 'boolean') throw new SchemaError('DEFAULT must be a boolean', path);
      return;
    case 'integer':
    case 'enum':
      if (typeof value !== 'number' && typeof value !== 'bigint')
        throw new SchemaError('DEFAULT must be a number', path);
      return;
    case 'utf8String':
    case 'oid':
      if (typeof value !== 'string') throw new SchemaError('DEFAULT must be a string', path);
      return;
    case 'null':
      if (value !== null) throw new SchemaError('DEFAULT must be null', path);
      return;
    default:
      throw new SchemaError(`DEFAULT is not supported for ${node.kind}`, path);
  }
};

// ---------------------------------------------------------------------------
// Field constraint compilation
// ---------------------------------------------------------------------------

const compileFields = (
  ctx: CompileCtx,
  fields: Field[],
  path: string,
  ordered: boolean,
): FieldPlan[] => {
  const plans: FieldPlan[] = [];
  const seenNames = new Set<string>();
  // Tags claimed by earlier OPTIONAL/DEFAULT fields. In an ordered container a
  // required field pins its position, so only a non-required predecessor makes
  // "does this TLV belong to me or the next field?" undecidable (X.680 25.3).
  const claimedOptional = new Map<string, string>(); // tagKey -> field name
  // In an unordered container (SET) any shared tag between members is ambiguous.
  const claimedAll = new Map<string, string>();

  for (const field of fields) {
    const fieldPath = `${path}.${field.name}`;
    if (seenNames.has(field.name)) throw new SchemaError(`duplicate field "${field.name}"`, fieldPath);
    seenNames.add(field.name);
    if (field.optional && field.default !== undefined)
      throw new SchemaError('field cannot be both OPTIONAL and DEFAULT', fieldPath);

    const plan = compileNode(ctx, field.type, fieldPath);
    const dispatch = dispatchTags(ctx, field.type, []);
    if (dispatch.length === 0)
      throw new SchemaError('field type has no decodable head tag (bare recursive ref?)', fieldPath);

    const fp: FieldPlan = {
      name: field.name,
      required: !field.optional && field.default === undefined,
      hasDefault: field.default !== undefined,
      plan,
      dispatch,
    };
    if (field.default !== undefined) {
      validateDefault(field.default, field.type, fieldPath);
      fp.defaultValue = field.default;
    }

    // Tag-dispatch conflicts: this is where OPTIONAL/CHOICE ambiguity is
    // caught statically — an OPTIONAL or untagged CHOICE whose tag set
    // intersects a sibling's makes member attribution undecidable.
    for (const tag of dispatch) {
      const key = tagKey(tag);
      const optionalOwner = claimedOptional.get(key);
      if (optionalOwner !== undefined) {
        throw new SchemaError(
          `ambiguous tag [${tag.tagClass} ${tag.tagNumber}]: optional "${optionalOwner}" is indistinguishable from "${field.name}"`,
          fieldPath,
        );
      }
      if (!ordered) {
        const owner = claimedAll.get(key);
        if (owner !== undefined) {
          throw new SchemaError(
            `ambiguous tag [${tag.tagClass} ${tag.tagNumber}]: claimed by both "${owner}" and "${field.name}"`,
            fieldPath,
          );
        }
        claimedAll.set(key, field.name);
      }
      if (!fp.required) claimedOptional.set(key, field.name);
    }
    plans.push(fp);
  }
  return plans;
};

// ---------------------------------------------------------------------------
// Node compilation
// ---------------------------------------------------------------------------

const checkTagging = (node: SchemaNode, path: string): void => {
  if (!node.tag) return;
  if (node.kind === 'choice' && node.implicit)
    throw new SchemaError('CHOICE cannot be implicitly tagged', path);
  if (node.kind === 'choice' && node.tag.class === 'universal')
    throw new SchemaError('CHOICE cannot carry a universal explicit tag', path);
  if (node.implicit && node.kind === 'ref')
    throw new SchemaError('implicit tagging of a named ref is not supported (tag it explicitly)', path);
};

const implicitOuter = (node: SchemaNode): WireTag => {
  if (node.tag && node.implicit) return { tagClass: tagClassOf(node.tag), tagNumber: node.tag.number };
  return { tagClass: TagClass.Universal, tagNumber: universalOf(node) };
};

const compileNode = (ctx: CompileCtx, node: SchemaNode, path: string): Plan => {
  checkTagging(node, path);
  const explicit: WireTag | undefined =
    node.tag && (node.kind === 'choice' || !node.implicit)
      ? { tagClass: tagClassOf(node.tag), tagNumber: node.tag.number }
      : undefined;

  switch (node.kind) {
    case 'sequence': {
      const fields = compileFields(ctx, node.fields, path, true);
      return { kind: 'sequence', path, fields, explicit, outer: explicit ?? implicitOuter(node) };
    }
    case 'set': {
      const fields = compileFields(ctx, node.fields, path, false);
      const byTag = new Map<string, FieldPlan>();
      for (const f of fields) for (const t of f.dispatch) byTag.set(tagKey(t), f);
      return { kind: 'set', path, fields, byTag, explicit, outer: explicit ?? implicitOuter(node) };
    }
    case 'sequenceOf': {
      const element = compileNode(ctx, node.element, `${path}[]`);
      return { kind: 'sequenceOf', path, element, explicit, outer: explicit ?? implicitOuter(node) };
    }
    case 'choice':
      return compileChoice(ctx, node, path, explicit);
    case 'ref':
      if (!ctx.named[node.name])
        throw new SchemaError(`unknown named type "${node.name}"`, path);
      return {
        kind: 'ref',
        path,
        name: node.name,
        // Late binding: named plans are all registered before decoding runs.
        target: () => {
          const plan = ctx.namedPlans.get(node.name);
          if (!plan) throw new SchemaError(`unknown named type "${node.name}"`, path);
          return plan;
        },
        explicit,
        outer: explicit ?? { tagClass: TagClass.Universal, tagNumber: 0 },
      };
    default: {
      const p = node as PrimitiveNode;
      return {
        kind: p.kind,
        path,
        implicit: !!p.implicit && !!p.tag,
        explicit,
        outer: explicit ?? implicitOuter(node),
      };
    }
  }
};

const compileChoice = (
  ctx: CompileCtx,
  node: ChoiceNode,
  path: string,
  explicit: WireTag | undefined,
): ChoicePlan => {
  if (node.alternatives.length === 0)
    throw new SchemaError('CHOICE needs at least one alternative', path);
  const alternatives: Plan[] = [];
  const byTag = new Map<string, Plan>();
  for (let i = 0; i < node.alternatives.length; i++) {
    const alt = node.alternatives[i];
    const altPath = `${path}<${i}>`;
    if (alt.kind === 'choice' && !alt.tag)
      throw new SchemaError('nested untagged CHOICE: flatten the alternatives instead', altPath);
    const plan = compileNode(ctx, alt, altPath);
    for (const tag of dispatchTags(ctx, alt, [])) {
      const key = tagKey(tag);
      if (byTag.has(key)) {
        throw new SchemaError(
          `ambiguous CHOICE: alternatives share tag [${tag.tagClass} ${tag.tagNumber}]`,
          altPath,
        );
      }
      byTag.set(key, plan);
    }
    alternatives.push(plan);
  }
  const outer = explicit ?? { tagClass: TagClass.Universal, tagNumber: 0 };
  return { kind: 'choice', path, alternatives, byTag, explicit, outer };
};

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

export const compileSchema = (root: SchemaNode, options: CompileOptions = {}): CompiledSchema => {
  const ctx: CompileCtx = { named: options.named ?? {}, namedPlans: new Map() };
  const maxDepth = options.maxDepth ?? DEFAULT_MAX_DEPTH;

  for (const [name, def] of Object.entries(ctx.named)) {
    if (def.kind === 'ref') throw new SchemaError('named type cannot be an alias to another ref', name);
    ctx.namedPlans.set(name, compileNode(ctx, def, `#${name}`));
  }
  const rootPlan = compileNode(ctx, root, '$');
  return { root: rootPlan, named: ctx.namedPlans, maxDepth };
};
