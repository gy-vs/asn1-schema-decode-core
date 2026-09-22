/**
 * Decode phase: walks a compiled plan over the byte buffer. Every decoded
 * value keeps its original byte range (`span`) and the schema path that
 * produced it; errors carry both the schema path and the byte offset.
 */

import {
  ChoicePlan,
  CompiledSchema,
  FieldPlan,
  Plan,
  PrimitivePlan,
  SequencePlan,
  SequenceOfPlan,
  SetPlan,
  WireTag,
} from './compile.js';
import { decodeIntegerContent, readHeader, TagClass, TlvError, TlvHeader, UniversalTag } from './tlv.js';

export class DerDecodeError extends Error {
  constructor(
    message: string,
    readonly schemaPath: string,
    readonly offset: number,
  ) {
    super(`${message} (at ${schemaPath}, offset ${offset})`);
    this.name = 'DerDecodeError';
  }
}

export interface Span {
  start: number;
  end: number;
}

interface BaseValue {
  /** Byte range of the whole TLV (tag..end of content) in the input. */
  span: Span;
  /** Byte range of the content octets. */
  content: Span;
  /** Schema path of the node that produced this value. */
  path: string;
}

export interface BooleanValue extends BaseValue {
  kind: 'boolean';
  value: boolean;
}
export interface IntegerValue extends BaseValue {
  kind: 'integer' | 'enum';
  value: bigint;
}
export interface BytesValue extends BaseValue {
  kind: 'octetString' | 'bitString';
  value: Uint8Array;
}
export interface NullValue extends BaseValue {
  kind: 'null';
  value: null;
}
export interface StringValue extends BaseValue {
  kind: 'utf8String' | 'oid';
  value: string;
}
export interface SequenceValue extends BaseValue {
  kind: 'sequence' | 'set';
  fields: Record<string, Value>;
  /** Names of fields that were filled from DEFAULT (absent on the wire). */
  defaulted: string[];
  /** Unrecognized trailing TLVs (extension data), kept as raw spans. */
  extensions: Span[];
}
export interface SequenceOfValue extends BaseValue {
  kind: 'sequenceOf';
  items: Value[];
}
export interface ChoiceValue extends BaseValue {
  kind: 'choice';
  /** Index into the compiled alternatives array. */
  alternative: number;
  value: Value;
}

export type Value =
  | BooleanValue
  | IntegerValue
  | BytesValue
  | NullValue
  | StringValue
  | SequenceValue
  | SequenceOfValue
  | ChoiceValue;

interface Cursor {
  pos: number;
  end: number;
}

interface DecodeContext {
  data: Uint8Array;
  maxDepth: number;
}

const tagMatches = (h: TlvHeader, t: WireTag): boolean =>
  h.tagClass === t.tagClass && h.tagNumber === t.tagNumber;

const fail: (ctx: DecodeContext, path: string, offset: number, message: string) => never = (
  ctx,
  path,
  offset,
  message,
) => {
  throw new DerDecodeError(message, path, offset);
};

/** readHeader, but re-raised with the schema path of the enclosing construct. */
const read = (ctx: DecodeContext, path: string, pos: number): TlvHeader => {
  try {
    return readHeader(ctx.data, pos);
  } catch (e) {
    if (e instanceof TlvError) throw new DerDecodeError(e.message, path, e.offset);
    throw e;
  }
};

const expectTag = (ctx: DecodeContext, plan: Plan, h: TlvHeader, want: WireTag, what: string): void => {
  if (!tagMatches(h, want)) {
    fail(
      ctx,
      plan.path,
      h.start,
      `expected ${what} tag [${want.tagClass} ${want.tagNumber}], got [${h.tagClass} ${h.tagNumber}]`,
    );
  }
};

/** Strip an explicit wrapper and return the inner header. */
const unwrapExplicit = (ctx: DecodeContext, plan: Plan, h: TlvHeader): TlvHeader => {
  if (!plan.explicit) return h;
  expectTag(ctx, plan, h, plan.explicit, 'explicit');
  if (!h.constructed) fail(ctx, plan.path, h.start, 'explicit tag must be constructed');
  const inner = read(ctx, plan.path, h.contentStart);
  if (inner.end !== h.end)
    fail(ctx, plan.path, inner.end, 'explicit tag must wrap exactly one TLV');
  return inner;
};

const decodePrimitive = (
  ctx: DecodeContext,
  plan: PrimitivePlan,
  h: TlvHeader,
): Value => {
  const { data } = ctx;
  const base = {
    span: { start: h.start, end: h.end },
    content: { start: h.contentStart, end: h.end },
    path: plan.path,
  };
  switch (plan.kind) {
    case 'boolean': {
      if (h.contentLength !== 1) fail(ctx, plan.path, h.start, 'BOOLEAN must have length 1');
      return { kind: 'boolean', value: data[h.contentStart] !== 0, ...base };
    }
    case 'integer':
    case 'enum':
      return { kind: plan.kind, value: decodeIntegerContent(data, h.contentStart, h.end), ...base };
    case 'octetString':
      return { kind: 'octetString', value: data.slice(h.contentStart, h.end), ...base };
    case 'bitString': {
      if (h.contentLength < 1) fail(ctx, plan.path, h.start, 'BIT STRING needs an unused-bits octet');
      return { kind: 'bitString', value: data.slice(h.contentStart + 1, h.end), ...base };
    }
    case 'null': {
      if (h.contentLength !== 0) fail(ctx, plan.path, h.start, 'NULL must be empty');
      return { kind: 'null', value: null, ...base };
    }
    case 'oid': {
      return { kind: 'oid', value: decodeOid(data, h.contentStart, h.end), ...base };
    }
    case 'utf8String': {
      const text = new TextDecoder('utf-8', { fatal: true }).decode(
        data.subarray(h.contentStart, h.end),
      );
      return { kind: 'utf8String', value: text, ...base };
    }
  }
};

const decodeOid = (data: Uint8Array, start: number, end: number): string => {
  if (start >= end) return '';
  const arcs: number[] = [];
  const first = data[start];
  const arc0 = first < 40 ? 0 : first < 80 ? 1 : 2;
  arcs.push(arc0, first - arc0 * 40);
  let value = 0;
  for (let i = start + 1; i < end; i++) {
    value = value * 128 + (data[i] & 0x7f);
    if ((data[i] & 0x80) === 0) {
      arcs.push(value);
      value = 0;
    }
  }
  return arcs.join('.');
};

const decodeSequence = (
  ctx: DecodeContext,
  plan: SequencePlan,
  h: TlvHeader,
  depth: number,
): SequenceValue => {
  const cursor: Cursor = { pos: h.contentStart, end: h.end };
  const fields: Record<string, Value> = {};
  const defaulted: string[] = [];
  const extensions: Span[] = [];

  for (const field of plan.fields) {
    if (cursor.pos < cursor.end) {
      const head = read(ctx, plan.path, cursor.pos);
      if (field.dispatch.some((t) => tagMatches(head, t))) {
        fields[field.name] = decodePlan(ctx, field.plan, head, depth + 1);
        cursor.pos = head.end;
        continue;
      }
    }
    if (field.required) {
      fail(ctx, field.plan.path, cursor.pos, `missing required field "${field.name}"`);
    }
    if (field.hasDefault) {
      // Absent DEFAULT: synthesize the value; never confused with an explicit
      // encoding because an explicitly encoded default still arrives on the
      // wire and is decoded above.
      fields[field.name] = defaultValue(ctx, field);
      defaulted.push(field.name);
    }
  }

  // Anything left is extension data unknown to this schema version.
  while (cursor.pos < cursor.end) {
    const head = read(ctx, plan.path, cursor.pos);
    extensions.push({ start: head.start, end: head.end });
    cursor.pos = head.end;
  }

  return {
    kind: 'sequence',
    span: { start: h.start, end: h.end },
    content: { start: h.contentStart, end: h.end },
    path: plan.path,
    fields,
    defaulted,
    extensions,
  };
};

const decodeSet = (
  ctx: DecodeContext,
  plan: SetPlan,
  h: TlvHeader,
  depth: number,
): SequenceValue => {
  const cursor: Cursor = { pos: h.contentStart, end: h.end };
  const fields: Record<string, Value> = {};
  const defaulted: string[] = [];
  const seen = new Set<string>();

  while (cursor.pos < cursor.end) {
    const head = read(ctx, plan.path, cursor.pos);
    const key = `${head.tagClass}:${head.tagNumber}`;
    const field = plan.byTag.get(key);
    if (!field) fail(ctx, plan.path, head.start, `unexpected SET member tag [${key}]`);
    if (seen.has(field.name))
      fail(ctx, field.plan.path, head.start, `duplicate SET member "${field.name}"`);
    seen.add(field.name);
    fields[field.name] = decodePlan(ctx, field.plan, head, depth + 1);
    cursor.pos = head.end;
  }

  for (const field of plan.fields) {
    if (seen.has(field.name)) continue;
    if (field.required) fail(ctx, field.plan.path, h.end, `missing required field "${field.name}"`);
    if (field.hasDefault) {
      fields[field.name] = defaultValue(ctx, field);
      defaulted.push(field.name);
    }
  }

  return {
    kind: 'set',
    span: { start: h.start, end: h.end },
    content: { start: h.contentStart, end: h.end },
    path: plan.path,
    fields,
    defaulted,
    extensions: [],
  };
};

const decodeSequenceOf = (
  ctx: DecodeContext,
  plan: SequenceOfPlan,
  h: TlvHeader,
  depth: number,
): SequenceOfValue => {
  const items: Value[] = [];
  let pos = h.contentStart;
  while (pos < h.end) {
    const head = read(ctx, plan.path, pos);
    items.push(decodePlan(ctx, plan.element, head, depth + 1));
    pos = head.end;
  }
  return {
    kind: 'sequenceOf',
    span: { start: h.start, end: h.end },
    content: { start: h.contentStart, end: h.end },
    path: plan.path,
    items,
  };
};

const decodeChoice = (
  ctx: DecodeContext,
  plan: ChoicePlan,
  h: TlvHeader,
  depth: number,
): ChoiceValue => {
  const key = `${h.tagClass}:${h.tagNumber}`;
  const alt = plan.byTag.get(key);
  if (!alt) fail(ctx, plan.path, h.start, `no CHOICE alternative for tag [${key}]`);
  const value = decodePlan(ctx, alt, h, depth + 1);
  return {
    kind: 'choice',
    span: value.span,
    content: value.content,
    path: plan.path,
    alternative: plan.alternatives.indexOf(alt),
    value,
  };
};

/** Synthesize the compile-time-validated DEFAULT for an absent field. */
const defaultValue = (ctx: DecodeContext, field: FieldPlan): Value => {
  const plan = field.plan;
  const span = { start: -1, end: -1 }; // not present on the wire
  const base = { span, content: span, path: plan.path };
  const v = field.defaultValue;
  switch (plan.kind) {
    case 'boolean':
      return { kind: 'boolean', value: v as boolean, ...base };
    case 'integer':
    case 'enum':
      return { kind: plan.kind, value: BigInt(v as number | bigint), ...base };
    case 'utf8String':
    case 'oid':
      return { kind: plan.kind, value: v as string, ...base };
    case 'null':
      return { kind: 'null', value: null, ...base };
    default:
      return fail(ctx, plan.path, -1, 'unsupported DEFAULT kind');
  }
};

const decodePlan = (ctx: DecodeContext, plan: Plan, h: TlvHeader, depth: number): Value => {
  if (depth > ctx.maxDepth) {
    fail(ctx, plan.path, h.start, `nesting depth budget exceeded (max ${ctx.maxDepth})`);
  }
  switch (plan.kind) {
    case 'ref':
      return decodePlan(ctx, plan.target(), unwrapExplicit(ctx, plan, h), depth);
    case 'choice':
      return decodeChoice(ctx, plan, unwrapExplicit(ctx, plan, h), depth);
    case 'sequence': {
      const inner = unwrapExplicit(ctx, plan, h);
      expectTag(ctx, plan, inner, plan.explicit ? innerTag(plan) : plan.outer, 'SEQUENCE');
      if (!inner.constructed) fail(ctx, plan.path, inner.start, 'SEQUENCE must be constructed');
      return decodeSequence(ctx, plan, inner, depth);
    }
    case 'set': {
      const inner = unwrapExplicit(ctx, plan, h);
      expectTag(ctx, plan, inner, plan.explicit ? innerTag(plan) : plan.outer, 'SET');
      if (!inner.constructed) fail(ctx, plan.path, inner.start, 'SET must be constructed');
      return decodeSet(ctx, plan, inner, depth);
    }
    case 'sequenceOf': {
      const inner = unwrapExplicit(ctx, plan, h);
      expectTag(ctx, plan, inner, plan.explicit ? innerTag(plan) : plan.outer, 'SEQUENCE OF');
      if (!inner.constructed) fail(ctx, plan.path, inner.start, 'SEQUENCE OF must be constructed');
      return decodeSequenceOf(ctx, plan, inner, depth);
    }
    default: {
      const inner = unwrapExplicit(ctx, plan, h);
      expectTag(ctx, plan, inner, plan.explicit ? innerTag(plan) : plan.outer, plan.kind);
      if (inner.constructed)
        fail(ctx, plan.path, inner.start, `constructed encoding of primitive ${plan.kind}`);
      try {
        return decodePrimitive(ctx, plan, inner);
      } catch (e) {
        if (e instanceof TlvError) throw new DerDecodeError(e.message, plan.path, e.offset);
        throw e;
      }
    }
  }
};

/** The tag a plan's own content carries inside an explicit wrapper. */
const innerTag = (plan: Plan): WireTag => {
  switch (plan.kind) {
    case 'sequence':
    case 'sequenceOf':
      return { tagClass: TagClass.Universal, tagNumber: UniversalTag.Sequence };
    case 'set':
      return { tagClass: TagClass.Universal, tagNumber: UniversalTag.Set };
    case 'choice':
      // An explicitly tagged CHOICE wraps the chosen alternative's own tag;
      // decodeChoice dispatches on whatever tag appears, so this is unused.
      return { tagClass: TagClass.Universal, tagNumber: 0 };
    case 'ref':
      return { tagClass: TagClass.Universal, tagNumber: 0 };
    default:
      return { tagClass: TagClass.Universal, tagNumber: primitiveUniversal(plan.kind) };
  }
};

const primitiveUniversal = (kind: PrimitivePlan['kind']): number => {
  switch (kind) {
    case 'boolean':
      return 1;
    case 'integer':
    case 'enum':
      return 2;
    case 'bitString':
      return 3;
    case 'octetString':
      return 4;
    case 'null':
      return 5;
    case 'oid':
      return 6;
    case 'utf8String':
      return 12;
  }
};

export interface DecodeOptions {
  /** Allow trailing bytes after the root TLV (default: reject). */
  allowTrailing?: boolean;
}

export const decode = (
  schema: CompiledSchema,
  data: Uint8Array,
  options: DecodeOptions = {},
): Value => {
  const ctx: DecodeContext = { data, maxDepth: schema.maxDepth };
  const header = read(ctx, schema.root.path, 0);
  const value = decodePlan(ctx, schema.root, header, 0);
  if (!options.allowTrailing && header.end !== data.length) {
    fail(ctx, schema.root.path, header.end, 'trailing bytes after root value');
  }
  return value;
};
