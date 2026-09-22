export type Tlv = { tag: number; length: number; value: Uint8Array };

/** @deprecated Low-level helper kept for backwards compatibility; see `readTlv` for DER-strict parsing. */
export function decodeTlv(data: Uint8Array): Tlv {
  if (data.length < 2) throw new Error('truncated');
  const tag = data[0],
    length = data[1];
  if (length & 128) throw new Error('long length unsupported');
  if (data.length < 2 + length) throw new Error('truncated');
  return { tag, length, value: data.slice(2, 2 + length) };
}

/** @deprecated Low-level helper kept for backwards compatibility; INTEGER decoding is built into `decode`. */
export function decodeInteger(bytes: Uint8Array) {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

export { DerError, DerDecodeError, SchemaCompileError } from './errors.js';
export { TAG_CLASS, readTlv, tagKey, describeTag } from './tlv.js';
export type { TagClassName, TlvHeader } from './tlv.js';
export type { AlternativeDef, CompileOptions, FieldDef, SchemaNode, TagSpec } from './schema.js';
export { compile } from './compile.js';
export type { CAlt, CField, CNode, CompiledSchema, Expect, PrimKind, TagSet } from './compile.js';
export { decode } from './decode.js';
export type { DecodeOptions, DecodedValue, Range, RawExtension } from './decode.js';
