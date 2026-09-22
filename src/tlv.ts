/**
 * Raw DER TLV reading. Everything here works on byte offsets so decoded
 * values can keep a reference to their original span in the input buffer.
 */

export const enum TagClass {
  Universal = 0,
  Application = 1,
  Context = 2,
  Private = 3,
}

/** Universal tag numbers used by the schema layer. */
export const enum UniversalTag {
  Boolean = 1,
  Integer = 2,
  BitString = 3,
  OctetString = 4,
  Null = 5,
  Oid = 6,
  Utf8String = 12,
  PrintableString = 19,
  Sequence = 16,
  Set = 17,
}

export interface TlvHeader {
  tagClass: TagClass;
  constructed: boolean;
  tagNumber: number;
  /** Offset of the identifier octets. */
  start: number;
  /** Offset of the content octets. */
  contentStart: number;
  /** Offset one past the last content octet. */
  end: number;
  contentLength: number;
}

export class TlvError extends Error {
  constructor(
    message: string,
    readonly offset: number,
  ) {
    super(message);
    this.name = 'TlvError';
  }
}

const readTagNumber = (data: Uint8Array, offset: number): { tagNumber: number; next: number } => {
  const first = data[offset];
  if ((first & 0x1f) !== 0x1f) return { tagNumber: first & 0x1f, next: offset + 1 };
  let tagNumber = 0;
  let cursor = offset + 1;
  for (;;) {
    if (cursor >= data.length) throw new TlvError('truncated high-tag-number form', offset);
    const byte = data[cursor++];
    tagNumber = tagNumber * 128 + (byte & 0x7f);
    if ((byte & 0x80) === 0) break;
  }
  return { tagNumber, next: cursor };
};

/** Read one TLV header at `offset`. Throws TlvError on truncation or indefinite length. */
export const readHeader = (data: Uint8Array, offset: number): TlvHeader => {
  if (offset >= data.length) throw new TlvError('truncated tag', offset);
  const first = data[offset];
  const { tagNumber, next } = readTagNumber(data, offset);
  if (next >= data.length) throw new TlvError('truncated length', offset);
  const lengthByte = data[next];
  let contentStart: number;
  let contentLength: number;
  if ((lengthByte & 0x80) === 0) {
    contentLength = lengthByte;
    contentStart = next + 1;
  } else {
    const count = lengthByte & 0x7f;
    if (count === 0) throw new TlvError('indefinite length is not DER', next);
    if (count > 4) throw new TlvError('length too large', next);
    if (next + 1 + count > data.length) throw new TlvError('truncated length', next);
    contentLength = 0;
    for (let i = 0; i < count; i++) contentLength = contentLength * 256 + data[next + 1 + i];
    contentStart = next + 1 + count;
  }
  const end = contentStart + contentLength;
  if (end > data.length) throw new TlvError('truncated content', offset);
  return {
    tagClass: (first >> 6) as TagClass,
    constructed: (first & 0x20) !== 0,
    tagNumber,
    start: offset,
    contentStart,
    end,
    contentLength,
  };
};

/** Decode a DER INTEGER content span to a bigint (two's complement). */
export const decodeIntegerContent = (data: Uint8Array, start: number, end: number): bigint => {
  if (start >= end) throw new TlvError('empty INTEGER', start);
  let value = 0n;
  for (let i = start; i < end; i++) value = (value << 8n) | BigInt(data[i]);
  if (data[start] & 0x80) value -= 1n << BigInt((end - start) * 8);
  return value;
};
