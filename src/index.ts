// Low-level TLV helpers (original API, kept for compatibility).
export type Tlv = { tag: number; length: number; value: Uint8Array };
export function decodeTlv(data: Uint8Array): Tlv {
  if (data.length < 2) throw new Error('truncated');
  const tag = data[0],
    length = data[1];
  if (length & 128) throw new Error('long length unsupported');
  if (data.length < 2 + length) throw new Error('truncated');
  return { tag, length, value: data.slice(2, 2 + length) };
}
export function decodeInteger(bytes: Uint8Array) {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

// Schema-driven DER decoding.
export * from './schema.js';
export * from './compile.js';
export * from './decode.js';
export { TagClass, UniversalTag, TlvError, readHeader } from './tlv.js';
export type { TlvHeader } from './tlv.js';
