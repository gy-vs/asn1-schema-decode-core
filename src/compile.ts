import { SchemaCompileError } from './errors.js';
import { TAG_CLASS, tagKey, type TagClassName } from './tlv.js';
import type { CompileOptions, FieldDef, SchemaNode, TagSpec } from './schema.js';

/** Universal tag numbers for the supported primitive and constructed types. */
const UNIVERSAL_TAG: Record<string, number> = {
  boolean: 1,
  integer: 2,
  'octet-string': 4,
  null: 5,
  oid: 6,
  'utf8-string': 12,
};
const SEQUENCE_TAG = 16;
const SET_TAG = 17;

/** The exact tag a node must see on the wire. */
export interface Expect {
  tagClass: number;
  tagNumber: number;
  constructed: boolean;
}

export type PrimKind = 'boolean' | 'integer' | 'octet-string' | 'null' | 'oid' | 'utf8-string';

/** Set of tags a node's encoding may start with; 'any' matches every tag. */
export type TagSet = ReadonlySet<string> | 'any';

export interface CField {
  name: string;
  node: CNode;
  optional: boolean;
  hasDefault: boolean;
  defaultValue: unknown;
}

export interface CAlt {
  name: string;
  node: CNode;
}

/**
 * Compiled schema graph. `ref` nodes stay as indirections so the decoder can
 * budget recursion depth. Container nodes carry their schema `path` for
 * error reporting; `byTag` dispatch tables are filled by the finalize pass.
 */
export type CNode =
  | { kind: 'primitive'; prim: PrimKind; expect: Expect }
  | { kind: 'any' }
  | { kind: 'sequence'; expect: Expect; fields: CField[]; extensible: boolean; path: string }
  | {
      kind: 'set';
      expect: Expect;
      fields: CField[];
      byTag: Map<string, CField>;
      anyField: CField | null;
      extensible: boolean;
      path: string;
    }
  | { kind: 'sequence-of'; expect: Expect; element: CNode }
  | { kind: 'choice'; alternatives: CAlt[]; byTag: Map<string, CAlt>; anyAlt: CAlt | null; path: string }
  | { kind: 'tagged'; expect: Expect; mode: 'explicit' | 'implicit'; inner: CNode }
  | { kind: 'ref'; name: string };

export interface CompiledSchema {
  root: CNode;
  types: ReadonlyMap<string, CNode>;
  name: string;
}

/**
 * Compiles a runtime schema: resolves named references, builds tag dispatch
 * tables, and rejects ambiguous or non-terminating schemas.
 *
 * Compile-time checks include:
 * - OPTIONAL/DEFAULT fields that cannot be distinguished from a following
 *   field by tag (SEQUENCE), and any two SET members or CHOICE alternatives
 *   whose tags overlap;
 * - IMPLICIT tagging of CHOICE or ANY;
 * - recursive type cycles that can never produce a finite value;
 * - unknown references, duplicate names, invalid tags, mismatched DEFAULTs.
 */
export function compile(root: SchemaNode, options: CompileOptions = {}): CompiledSchema {
  return new Compiler(options.types ?? {}).run(root, options.name ?? '$');
}

class Compiler {
  private readonly rawTypes: Record<string, SchemaNode>;
  private readonly compiled = new Map<string, CNode>();
  private readonly tagMemo = new Map<CNode, TagSet>();
  private readonly finalized = new Set<CNode>();

  constructor(types: Record<string, SchemaNode>) {
    this.rawTypes = types;
  }

  run(root: SchemaNode, rootName: string): CompiledSchema {
    // Phase 1: recursion must be able to terminate (checked on raw schemas).
    for (const [name, node] of Object.entries(this.rawTypes)) this.checkProductive(name, node);
    // Phase 2: build the graph. Tag dispatch needs the whole graph, so named
    // types are all built before any dispatch table is computed.
    for (const [name, node] of Object.entries(this.rawTypes)) {
      this.compiled.set(name, this.compileNode(node, name));
    }
    const compiledRoot = this.compileNode(root, rootName);
    // Phase 3: ambiguity checks and dispatch tables.
    this.finalize(compiledRoot);
    for (const node of this.compiled.values()) this.finalize(node);
    return { root: compiledRoot, types: this.compiled, name: rootName };
  }

  private compileNode(node: SchemaNode, path: string): CNode {
    switch (node.kind) {
      case 'boolean':
      case 'integer':
      case 'octet-string':
      case 'null':
      case 'oid':
      case 'utf8-string':
        return {
          kind: 'primitive',
          prim: node.kind,
          expect: { tagClass: TAG_CLASS.universal, tagNumber: UNIVERSAL_TAG[node.kind], constructed: false },
        };
      case 'any':
        return { kind: 'any' };
      case 'sequence':
        return {
          kind: 'sequence',
          expect: { tagClass: TAG_CLASS.universal, tagNumber: SEQUENCE_TAG, constructed: true },
          fields: this.compileFields(node.fields, path),
          extensible: node.extensible ?? false,
          path,
        };
      case 'set':
        return {
          kind: 'set',
          expect: { tagClass: TAG_CLASS.universal, tagNumber: SET_TAG, constructed: true },
          fields: this.compileFields(node.fields, path),
          byTag: new Map(),
          anyField: null,
          extensible: node.extensible ?? false,
          path,
        };
      case 'sequence-of':
        return {
          kind: 'sequence-of',
          expect: { tagClass: TAG_CLASS.universal, tagNumber: SEQUENCE_TAG, constructed: true },
          element: this.compileNode(node.element, `${path}[]`),
        };
      case 'choice': {
        if (node.alternatives.length === 0) {
          throw new SchemaCompileError('CHOICE must have at least one alternative', { path });
        }
        const seen = new Set<string>();
        const alternatives: CAlt[] = node.alternatives.map((alt) => {
          if (seen.has(alt.name)) {
            throw new SchemaCompileError(`duplicate CHOICE alternative name '${alt.name}'`, { path });
          }
          seen.add(alt.name);
          return { name: alt.name, node: this.compileNode(alt.type, `${path}.${alt.name}`) };
        });
        return { kind: 'choice', alternatives, byTag: new Map(), anyAlt: null, path };
      }
      case 'tagged':
        return this.compileTagged(node, path);
      case 'ref':
        if (!(node.name in this.rawTypes)) {
          throw new SchemaCompileError(`unknown type reference '${node.name}'`, { path });
        }
        return { kind: 'ref', name: node.name };
    }
  }

  /** Ambiguity checks and tag dispatch tables; runs once per node after the graph is complete. */
  private finalize(node: CNode): void {
    if (this.finalized.has(node)) return;
    this.finalized.add(node);
    switch (node.kind) {
      case 'sequence': {
        // An OPTIONAL/DEFAULT field must be distinguishable from every field
        // that could appear next: all fields up to and including the next
        // required one.
        for (let i = 0; i < node.fields.length; i++) {
          const field = node.fields[i];
          if (!field.optional && !field.hasDefault) continue;
          for (let j = i + 1; j < node.fields.length; j++) {
            const later = node.fields[j];
            const clash = overlap(this.tagsOf(field.node), this.tagsOf(later.node));
            if (clash !== null) {
              const kind = field.hasDefault ? 'DEFAULT' : 'OPTIONAL';
              throw new SchemaCompileError(
                `ambiguous: ${kind} field '${field.name}' is indistinguishable from field '${later.name}' (both can start with tag ${clash})`,
                { path: node.path },
              );
            }
            if (!later.optional && !later.hasDefault) break;
          }
        }
        for (const field of node.fields) this.finalize(field.node);
        break;
      }
      case 'set': {
        // SET members may arrive in any order, so every pair must be disjoint.
        for (let i = 0; i < node.fields.length; i++) {
          for (let j = i + 1; j < node.fields.length; j++) {
            const clash = overlap(this.tagsOf(node.fields[i].node), this.tagsOf(node.fields[j].node));
            if (clash !== null) {
              throw new SchemaCompileError(
                `ambiguous: SET members '${node.fields[i].name}' and '${node.fields[j].name}' both can start with tag ${clash}`,
                { path: node.path },
              );
            }
          }
        }
        for (const field of node.fields) {
          const tags = this.tagsOf(field.node);
          if (tags === 'any') node.anyField = field;
          else for (const key of tags) node.byTag.set(key, field);
          this.finalize(field.node);
        }
        break;
      }
      case 'sequence-of':
        this.finalize(node.element);
        break;
      case 'choice': {
        for (let i = 0; i < node.alternatives.length; i++) {
          for (let j = i + 1; j < node.alternatives.length; j++) {
            const clash = overlap(this.tagsOf(node.alternatives[i].node), this.tagsOf(node.alternatives[j].node));
            if (clash !== null) {
              throw new SchemaCompileError(
                `ambiguous: CHOICE alternatives '${node.alternatives[i].name}' and '${node.alternatives[j].name}' both can start with tag ${clash}`,
                { path: node.path },
              );
            }
          }
        }
        for (const alt of node.alternatives) {
          const tags = this.tagsOf(alt.node);
          if (tags === 'any') node.anyAlt = alt;
          else for (const key of tags) node.byTag.set(key, alt);
          this.finalize(alt.node);
        }
        break;
      }
      case 'tagged':
        this.finalize(node.inner);
        break;
      case 'ref':
        this.finalize(this.compiled.get(node.name)!);
        break;
      default:
        break;
    }
  }

  private compileTagged(node: { tag: TagSpec; mode: 'explicit' | 'implicit'; type: SchemaNode }, path: string): CNode {
    const { tag, mode } = node;
    if (!(tag.class in TAG_CLASS) || !Number.isInteger(tag.number) || tag.number < 0) {
      throw new SchemaCompileError(`invalid tag [${String(tag.class)} ${String(tag.number)}]`, { path });
    }
    const tagClass = TAG_CLASS[tag.class as TagClassName];
    if (mode === 'explicit') {
      return {
        kind: 'tagged',
        mode,
        expect: { tagClass, tagNumber: tag.number, constructed: true },
        inner: this.compileNode(node.type, path),
      };
    }
    // IMPLICIT replaces the outermost tag of the target, so the target must
    // have a tag of its own: CHOICE and ANY cannot be implicitly tagged.
    this.checkImplicitTarget(node.type, path);
    return {
      kind: 'tagged',
      mode,
      expect: { tagClass, tagNumber: tag.number, constructed: this.constructedOf(node.type, new Set()) },
      inner: this.compileNode(node.type, path),
    };
  }

  private compileFields(defs: FieldDef[], path: string): CField[] {
    const seen = new Set<string>();
    return defs.map((def) => {
      const fieldPath = `${path}.${def.name}`;
      if (seen.has(def.name)) {
        throw new SchemaCompileError(`duplicate field name '${def.name}'`, { path });
      }
      seen.add(def.name);
      const hasDefault = def.default !== undefined;
      if (def.optional && hasDefault) {
        throw new SchemaCompileError(`field '${def.name}' cannot be both OPTIONAL and DEFAULT`, { path: fieldPath });
      }
      if (hasDefault) this.validateDefault(def.type, def.default, fieldPath);
      return {
        name: def.name,
        node: this.compileNode(def.type, fieldPath),
        optional: def.optional ?? false,
        hasDefault,
        defaultValue: def.default,
      };
    });
  }

  /** Tags a compiled node's encoding may start with. Cycles contribute nothing (least fixed point). */
  private tagsOf(node: CNode, visiting: Set<string> = new Set()): TagSet {
    const memoized = this.tagMemo.get(node);
    if (memoized !== undefined) return memoized;
    let result: TagSet;
    switch (node.kind) {
      case 'primitive':
      case 'sequence':
      case 'set':
      case 'sequence-of':
      case 'tagged':
        result = new Set([tagKey(node.expect.tagClass, node.expect.tagNumber)]);
        break;
      case 'any':
        result = 'any';
        break;
      case 'choice': {
        const acc = new Set<string>();
        let any = false;
        for (const alt of node.alternatives) {
          const tags = this.tagsOf(alt.node, visiting);
          if (tags === 'any') any = true;
          else for (const key of tags) acc.add(key);
        }
        result = any ? 'any' : acc;
        break;
      }
      case 'ref': {
        if (visiting.has(node.name)) return new Set(); // cycle: adds no new tags
        visiting.add(node.name);
        result = this.tagsOf(this.compiled.get(node.name)!, visiting);
        visiting.delete(node.name);
        break;
      }
    }
    this.tagMemo.set(node, result);
    return result;
  }

  /**
   * A type is productive if it can encode a finite value. Recursion through
   * OPTIONAL/DEFAULT fields, CHOICE alternatives or SEQUENCE OF can terminate;
   * a cycle of only required singular fields cannot.
   */
  private checkProductive(name: string, node: SchemaNode): void {
    if (!this.isProductive(node, new Set([name]))) {
      throw new SchemaCompileError(`unproductive recursion: type '${name}' can never produce a finite value`, {
        path: name,
      });
    }
  }

  private isProductive(node: SchemaNode, visiting: Set<string>): boolean {
    switch (node.kind) {
      case 'ref': {
        if (visiting.has(node.name)) return false;
        const target = this.rawTypes[node.name];
        if (!target) return true; // unknown refs are reported during compilation
        visiting.add(node.name);
        const result = this.isProductive(target, visiting);
        visiting.delete(node.name);
        return result;
      }
      case 'sequence':
      case 'set':
        return node.fields.every(
          (f) => f.optional || f.default !== undefined || this.isProductive(f.type, visiting),
        );
      case 'sequence-of':
        return true; // empty encoding terminates
      case 'choice':
        return node.alternatives.some((a) => this.isProductive(a.type, visiting));
      case 'tagged':
        return this.isProductive(node.type, visiting);
      default:
        return true;
    }
  }

  /** Rejects IMPLICIT tagging of CHOICE/ANY, looking through refs and nested IMPLICIT tags. */
  private checkImplicitTarget(type: SchemaNode, path: string): void {
    let node = type;
    const seen = new Set<string>();
    for (;;) {
      if (node.kind === 'ref') {
        if (seen.has(node.name)) return; // cycle: productivity check reports it
        seen.add(node.name);
        const target = this.rawTypes[node.name];
        if (!target) return; // unknown refs are reported during compilation
        node = target;
        continue;
      }
      if (node.kind === 'tagged') {
        // [T] IMPLICIT ([T2] EXPLICIT X) is equivalent to [T] EXPLICIT X — allowed.
        if (node.mode === 'explicit') return;
        node = node.type;
        continue;
      }
      break;
    }
    if (node.kind === 'choice' || node.kind === 'any') {
      throw new SchemaCompileError(`IMPLICIT tagging cannot be applied to ${node.kind.toUpperCase()}`, { path });
    }
  }

  /** Constructed bit of a type's outermost encoding, looking through refs. */
  private constructedOf(node: SchemaNode, visiting: Set<string>): boolean {
    switch (node.kind) {
      case 'ref': {
        if (visiting.has(node.name)) return false; // unreachable after the productivity check
        visiting.add(node.name);
        const result = this.constructedOf(this.rawTypes[node.name], visiting);
        visiting.delete(node.name);
        return result;
      }
      case 'tagged':
        return node.mode === 'explicit' ? true : this.constructedOf(node.type, visiting);
      case 'sequence':
      case 'set':
      case 'sequence-of':
        return true;
      default:
        return false;
    }
  }

  private validateDefault(type: SchemaNode, value: unknown, path: string): void {
    let node = type;
    const seen = new Set<string>();
    for (;;) {
      if (node.kind === 'ref') {
        if (seen.has(node.name)) return;
        seen.add(node.name);
        const target = this.rawTypes[node.name];
        if (!target) return;
        node = target;
        continue;
      }
      if (node.kind === 'tagged') {
        node = node.type;
        continue;
      }
      break;
    }
    const ok = (() => {
      switch (node.kind) {
        case 'integer':
          return typeof value === 'bigint' || (typeof value === 'number' && Number.isInteger(value));
        case 'boolean':
          return typeof value === 'boolean';
        case 'utf8-string':
        case 'oid':
          return typeof value === 'string';
        case 'octet-string':
          return value instanceof Uint8Array;
        case 'null':
          return value === null;
        default:
          return true; // constructed/choice/any defaults are not validated
      }
    })();
    if (!ok) {
      throw new SchemaCompileError(`DEFAULT value does not match type '${node.kind}'`, { path });
    }
  }
}

/** Returns a clashing tag key, 'any tag' for a wildcard clash, or null when disjoint. */
function overlap(a: TagSet, b: TagSet): string | null {
  if (a === 'any' || b === 'any') return 'any tag';
  for (const key of a) if (b.has(key)) return key;
  return null;
}
