import { DerDecodeError } from './errors.js';
import { describeTag, readTlv, tagKey, type TlvHeader } from './tlv.js';
import type { CField, CNode, CompiledSchema, Expect, PrimKind } from './compile.js';

/** Byte range into the decoded input, `[start, end)`. */
export interface Range {
  start: number;
  end: number;
}

/** A TLV that matched no declared field of an extensible SEQUENCE/SET. */
export interface RawExtension {
  tagClass: number;
  tagNumber: number;
  constructed: boolean;
  range: Range;
  raw: Uint8Array;
}

/**
 * Decoded value tree. Every node carries the byte range it occupied in the
 * input. For SEQUENCE/SET, `present[name]` tells whether a field was actually
 * encoded: an absent OPTIONAL leaves no entry in `fields`, while an absent
 * DEFAULT is filled in as `{ kind: 'default' }` — never confused with an
 * explicitly encoded value equal to the default.
 */
export type DecodedValue =
  | { kind: 'integer'; value: bigint; range: Range }
  | { kind: 'boolean'; value: boolean; range: Range }
  | { kind: 'octet-string'; value: Uint8Array; range: Range }
  | { kind: 'utf8-string'; value: string; range: Range }
  | { kind: 'null'; value: null; range: Range }
  | { kind: 'oid'; value: string; range: Range }
  | {
      kind: 'sequence' | 'set';
      fields: Record<string, DecodedValue>;
      present: Record<string, boolean>;
      extensions: RawExtension[];
      range: Range;
    }
  | { kind: 'sequence-of'; items: DecodedValue[]; range: Range }
  | { kind: 'choice'; name: string; value: DecodedValue; range: Range }
  | { kind: 'any'; tagClass: number; tagNumber: number; constructed: boolean; raw: Uint8Array; range: Range }
  | { kind: 'default'; value: unknown; range: null };

export interface DecodeOptions {
  /**
   * Maximum number of nested named-type (`ref`) resolutions. Recursion is
   * only possible through `ref`, so this bounds the depth of recursive
   * values. Defaults to 64.
   */
  maxDepth?: number;
}

const DEFAULT_MAX_DEPTH = 64;

interface Ctx {
  data: Uint8Array;
  types: ReadonlyMap<string, CNode>;
  maxDepth: number;
  depth: number;
}

/** Decodes `data` against a compiled schema. Throws `DerDecodeError` with schema path and byte offset. */
export function decode(schema: CompiledSchema, data: Uint8Array, options: DecodeOptions = {}): DecodedValue {
  const ctx: Ctx = { data, types: schema.types, maxDepth: options.maxDepth ?? DEFAULT_MAX_DEPTH, depth: 0 };
  const tlv = readTlv(data, 0, data.length);
  const value = decodeNode(schema.root, tlv, ctx, schema.name);
  if (tlv.end !== data.length) {
    throw new DerDecodeError('trailing data after top-level value', { offset: tlv.end, path: schema.name });
  }
  return value;
}

function decodeNode(node: CNode, tlv: TlvHeader, ctx: Ctx, path: string): DecodedValue {
  switch (node.kind) {
    case 'primitive':
      expectTag(node.expect, tlv, path);
      return decodePrimitive(node.prim, tlv, ctx, path);
    case 'any':
      return {
        kind: 'any',
        tagClass: tlv.tagClass,
        tagNumber: tlv.tagNumber,
        constructed: tlv.constructed,
        raw: ctx.data.slice(tlv.start, tlv.end),
        range: { start: tlv.start, end: tlv.end },
      };
    case 'sequence':
      expectTag(node.expect, tlv, path);
      return decodeSequence(node, tlv, ctx, path);
    case 'set':
      expectTag(node.expect, tlv, path);
      return decodeSet(node, tlv, ctx, path);
    case 'sequence-of':
      expectTag(node.expect, tlv, path);
      return decodeSequenceOf(node, tlv, ctx, path);
    case 'choice':
      return decodeChoice(node, tlv, ctx, path);
    case 'tagged':
      expectTag(node.expect, tlv, path);
      if (node.mode === 'explicit') return decodeExplicit(node.inner, tlv, ctx, path);
      return decodeImplicitContent(node.inner, tlv, ctx, path);
    case 'ref': {
      if (ctx.depth >= ctx.maxDepth) {
        throw new DerDecodeError(`recursion depth budget exceeded at type '${node.name}'`, {
          offset: tlv.start,
          path: `${path}.${node.name}`,
        });
      }
      ctx.depth++;
      try {
        return decodeNode(resolveRef(node, ctx), tlv, ctx, `${path}.${node.name}`);
      } finally {
        ctx.depth--;
      }
    }
  }
}

/**
 * Decodes a node whose own tag was replaced by an outer IMPLICIT tag; `tlv`
 * is the TLV carrying the replacing tag, its content is the node's content.
 */
function decodeImplicitContent(node: CNode, tlv: TlvHeader, ctx: Ctx, path: string): DecodedValue {
  switch (node.kind) {
    case 'primitive':
      return decodePrimitive(node.prim, tlv, ctx, path);
    case 'sequence':
      return decodeSequence(node, tlv, ctx, path);
    case 'set':
      return decodeSet(node, tlv, ctx, path);
    case 'sequence-of':
      return decodeSequenceOf(node, tlv, ctx, path);
    case 'ref': {
      if (ctx.depth >= ctx.maxDepth) {
        throw new DerDecodeError(`recursion depth budget exceeded at type '${node.name}'`, {
          offset: tlv.start,
          path: `${path}.${node.name}`,
        });
      }
      ctx.depth++;
      try {
        return decodeImplicitContent(resolveRef(node, ctx), tlv, ctx, `${path}.${node.name}`);
      } finally {
        ctx.depth--;
      }
    }
    case 'tagged':
      // [T] IMPLICIT ([T2] IMPLICIT X) ≡ [T] IMPLICIT X;
      // [T] IMPLICIT ([T2] EXPLICIT X) ≡ [T] EXPLICIT X.
      if (node.mode === 'implicit') return decodeImplicitContent(node.inner, tlv, ctx, path);
      return decodeExplicit(node.inner, tlv, ctx, path);
    default:
      // CHOICE and ANY are rejected by the compiler.
      throw new DerDecodeError(`cannot implicitly decode ${node.kind}`, { offset: tlv.start, path });
  }
}

/** Decodes an EXPLICIT wrapper: exactly one inner TLV, reported range covers the wrapper. */
function decodeExplicit(inner: CNode, tlv: TlvHeader, ctx: Ctx, path: string): DecodedValue {
  const innerTlv = readTlv(ctx.data, tlv.headerEnd, tlv.end);
  const value = decodeNode(inner, innerTlv, ctx, path);
  if (innerTlv.end !== tlv.end) {
    throw new DerDecodeError('unexpected extra content in EXPLICIT tag', { offset: innerTlv.end, path });
  }
  // decodeNode never yields a 'default' node, so widening range to Range is safe.
  return { ...value, range: { start: tlv.start, end: tlv.end } } as DecodedValue;
}

function decodeSequence(
  node: Extract<CNode, { kind: 'sequence' }>,
  tlv: TlvHeader,
  ctx: Ctx,
  path: string,
): DecodedValue {
  const fields: Record<string, DecodedValue> = {};
  const present: Record<string, boolean> = {};
  const extensions: RawExtension[] = [];
  let pos = tlv.headerEnd;

  for (let i = 0; i < node.fields.length; i++) {
    const field = node.fields[i];
    let consumed = false;
    while (pos < tlv.end) {
      const child = readTlv(ctx.data, pos, tlv.end);
      if (matches(field.node, child, ctx.types)) {
        fields[field.name] = decodeNode(field.node, child, ctx, `${path}.${field.name}`);
        present[field.name] = true;
        pos = child.end;
        consumed = true;
        break;
      }
      if (matchesAnyField(node.fields, i + 1, child, ctx.types)) break; // belongs to a later field
      if (node.extensible) {
        extensions.push(rawExtension(ctx.data, child));
        pos = child.end;
        continue;
      }
      if (!field.optional && !field.hasDefault) {
        throw new DerDecodeError(
          `missing required field '${field.name}'; found unexpected tag ${describeTag(child.tagClass, child.tagNumber, child.constructed)}`,
          { offset: child.start, path: `${path}.${field.name}` },
        );
      }
      throw new DerDecodeError(
        `unknown field with tag ${describeTag(child.tagClass, child.tagNumber, child.constructed)}`,
        { offset: child.start, path },
      );
    }
    if (consumed) continue;
    if (field.hasDefault) {
      fields[field.name] = { kind: 'default', value: field.defaultValue, range: null };
      present[field.name] = false;
    } else if (field.optional) {
      present[field.name] = false;
    } else {
      throw new DerDecodeError(`missing required field '${field.name}'`, {
        offset: pos,
        path: `${path}.${field.name}`,
      });
    }
  }

  while (pos < tlv.end) {
    const child = readTlv(ctx.data, pos, tlv.end);
    if (!node.extensible) {
      throw new DerDecodeError(
        `unknown extension field with tag ${describeTag(child.tagClass, child.tagNumber, child.constructed)}`,
        { offset: child.start, path },
      );
    }
    extensions.push(rawExtension(ctx.data, child));
    pos = child.end;
  }

  return { kind: 'sequence', fields, present, extensions, range: { start: tlv.start, end: tlv.end } };
}

function decodeSet(
  node: Extract<CNode, { kind: 'set' }>,
  tlv: TlvHeader,
  ctx: Ctx,
  path: string,
): DecodedValue {
  const fields: Record<string, DecodedValue> = {};
  const present: Record<string, boolean> = {};
  const extensions: RawExtension[] = [];
  const seen = new Set<string>();
  let pos = tlv.headerEnd;

  while (pos < tlv.end) {
    const child = readTlv(ctx.data, pos, tlv.end);
    const field = node.byTag.get(tagKey(child.tagClass, child.tagNumber)) ?? node.anyField;
    if (!field) {
      if (!node.extensible) {
        throw new DerDecodeError(
          `unknown SET member with tag ${describeTag(child.tagClass, child.tagNumber, child.constructed)}`,
          { offset: child.start, path },
        );
      }
      extensions.push(rawExtension(ctx.data, child));
      pos = child.end;
      continue;
    }
    if (seen.has(field.name)) {
      throw new DerDecodeError(`duplicate SET member '${field.name}'`, {
        offset: child.start,
        path: `${path}.${field.name}`,
      });
    }
    seen.add(field.name);
    fields[field.name] = decodeNode(field.node, child, ctx, `${path}.${field.name}`);
    present[field.name] = true;
    pos = child.end;
  }

  for (const field of node.fields) {
    if (seen.has(field.name)) continue;
    if (field.hasDefault) {
      fields[field.name] = { kind: 'default', value: field.defaultValue, range: null };
      present[field.name] = false;
    } else if (field.optional) {
      present[field.name] = false;
    } else {
      throw new DerDecodeError(`missing required SET member '${field.name}'`, {
        offset: tlv.end,
        path: `${path}.${field.name}`,
      });
    }
  }

  return { kind: 'set', fields, present, extensions, range: { start: tlv.start, end: tlv.end } };
}

function decodeSequenceOf(
  node: Extract<CNode, { kind: 'sequence-of' }>,
  tlv: TlvHeader,
  ctx: Ctx,
  path: string,
): DecodedValue {
  const items: DecodedValue[] = [];
  let pos = tlv.headerEnd;
  let index = 0;
  while (pos < tlv.end) {
    const child = readTlv(ctx.data, pos, tlv.end);
    items.push(decodeNode(node.element, child, ctx, `${path}[${index}]`));
    pos = child.end;
    index++;
  }
  return { kind: 'sequence-of', items, range: { start: tlv.start, end: tlv.end } };
}

function decodeChoice(
  node: Extract<CNode, { kind: 'choice' }>,
  tlv: TlvHeader,
  ctx: Ctx,
  path: string,
): DecodedValue {
  const alt = node.byTag.get(tagKey(tlv.tagClass, tlv.tagNumber)) ?? node.anyAlt;
  if (!alt) {
    throw new DerDecodeError(
      `no CHOICE alternative matches tag ${describeTag(tlv.tagClass, tlv.tagNumber, tlv.constructed)}`,
      { offset: tlv.start, path },
    );
  }
  return {
    kind: 'choice',
    name: alt.name,
    value: decodeNode(alt.node, tlv, ctx, `${path}.${alt.name}`),
    range: { start: tlv.start, end: tlv.end },
  };
}

function decodePrimitive(prim: PrimKind, tlv: TlvHeader, ctx: Ctx, path: string): DecodedValue {
  const bytes = ctx.data.subarray(tlv.headerEnd, tlv.end);
  const range = { start: tlv.start, end: tlv.end };
  switch (prim) {
    case 'integer': {
      if (bytes.length === 0) throw new DerDecodeError('empty INTEGER', { offset: tlv.start, path });
      if (bytes.length > 1) {
        const redundantPositive = bytes[0] === 0x00 && (bytes[1] & 0x80) === 0;
        const redundantNegative = bytes[0] === 0xff && (bytes[1] & 0x80) !== 0;
        if (redundantPositive || redundantNegative) {
          throw new DerDecodeError('non-minimal INTEGER encoding', { offset: tlv.start, path });
        }
      }
      let value = 0n;
      for (const byte of bytes) value = (value << 8n) | BigInt(byte);
      if (bytes[0] & 0x80) value -= 1n << BigInt(bytes.length * 8); // two's complement
      return { kind: 'integer', value, range };
    }
    case 'boolean': {
      if (bytes.length !== 1) throw new DerDecodeError('BOOLEAN must have length 1', { offset: tlv.start, path });
      if (bytes[0] !== 0x00 && bytes[0] !== 0xff) {
        throw new DerDecodeError('BOOLEAN must be encoded as 0x00 or 0xff in DER', { offset: tlv.start, path });
      }
      return { kind: 'boolean', value: bytes[0] === 0xff, range };
    }
    case 'null': {
      if (bytes.length !== 0) throw new DerDecodeError('NULL must have length 0', { offset: tlv.start, path });
      return { kind: 'null', value: null, range };
    }
    case 'octet-string':
      return { kind: 'octet-string', value: bytes.slice(), range };
    case 'utf8-string': {
      try {
        return { kind: 'utf8-string', value: new TextDecoder('utf-8', { fatal: true }).decode(bytes), range };
      } catch {
        throw new DerDecodeError('invalid UTF-8 in UTF8String', { offset: tlv.start, path });
      }
    }
    case 'oid':
      return { kind: 'oid', value: decodeOid(bytes, tlv, path), range };
  }
}

function decodeOid(bytes: Uint8Array, tlv: TlvHeader, path: string): string {
  if (bytes.length === 0) throw new DerDecodeError('empty OBJECT IDENTIFIER', { offset: tlv.start, path });
  const arcs: number[] = [];
  let pos = 0;
  while (pos < bytes.length) {
    if (bytes[pos] === 0x80) {
      throw new DerDecodeError('non-minimal OBJECT IDENTIFIER arc', { offset: tlv.start, path });
    }
    let value = 0;
    for (;;) {
      if (pos >= bytes.length) {
        throw new DerDecodeError('truncated OBJECT IDENTIFIER arc', { offset: tlv.start, path });
      }
      const b = bytes[pos++];
      value = value * 128 + (b & 0x7f);
      if (!Number.isSafeInteger(value)) {
        throw new DerDecodeError('OBJECT IDENTIFIER arc too large', { offset: tlv.start, path });
      }
      if ((b & 0x80) === 0) break;
    }
    arcs.push(value);
  }
  const first = arcs[0];
  const arc0 = first < 40 ? 0 : first < 80 ? 1 : 2;
  return [arc0, first - arc0 * 40, ...arcs.slice(1)].join('.');
}

function matches(node: CNode, tlv: TlvHeader, types: ReadonlyMap<string, CNode>): boolean {
  switch (node.kind) {
    case 'any':
      return true;
    case 'ref':
      return matches(types.get(node.name)!, tlv, types);
    case 'choice':
      return node.byTag.has(tagKey(tlv.tagClass, tlv.tagNumber)) || node.anyAlt !== null;
    default:
      return matchesExpect(node.expect, tlv);
  }
}

function matchesAnyField(fields: CField[], from: number, tlv: TlvHeader, types: ReadonlyMap<string, CNode>): boolean {
  for (let i = from; i < fields.length; i++) {
    if (matches(fields[i].node, tlv, types)) return true;
  }
  return false;
}

function matchesExpect(expect: Expect, tlv: TlvHeader): boolean {
  return (
    expect.tagClass === tlv.tagClass &&
    expect.tagNumber === tlv.tagNumber &&
    expect.constructed === tlv.constructed
  );
}

function expectTag(expect: Expect, tlv: TlvHeader, path: string): void {
  if (!matchesExpect(expect, tlv)) {
    throw new DerDecodeError(
      `tag mismatch: expected ${describeTag(expect.tagClass, expect.tagNumber, expect.constructed)}, ` +
        `found ${describeTag(tlv.tagClass, tlv.tagNumber, tlv.constructed)}`,
      { offset: tlv.start, path },
    );
  }
}

function resolveRef(node: Extract<CNode, { kind: 'ref' }>, ctx: Ctx): CNode {
  return ctx.types.get(node.name)!;
}

function rawExtension(data: Uint8Array, tlv: TlvHeader): RawExtension {
  return {
    tagClass: tlv.tagClass,
    tagNumber: tlv.tagNumber,
    constructed: tlv.constructed,
    range: { start: tlv.start, end: tlv.end },
    raw: data.slice(tlv.start, tlv.end),
  };
}
