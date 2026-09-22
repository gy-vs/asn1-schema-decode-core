import { DerDecodeError } from './errors.js';

/** BER/DER tag classes as encoded in bits 8-7 of the identifier octet. */
export const TAG_CLASS = { universal: 0, application: 1, context: 2, private: 3 } as const;
export type TagClassName = keyof typeof TAG_CLASS;

/** A parsed TLV header; all offsets are absolute positions into the input. */
export interface TlvHeader {
  tagClass: number;
  constructed: boolean;
  tagNumber: number;
  /** Offset of the first identifier octet. */
  start: number;
  /** Offset of the first content octet (one past the header). */
  headerEnd: number;
  /** Offset one past the last content octet. */
  end: number;
  /** Content length in bytes. */
  length: number;
}

/**
 * Reads one DER TLV header at `pos`, bounded by `end` (exclusive).
 * Enforces DER rules: no indefinite lengths, minimal length and tag encodings.
 */
export function readTlv(data: Uint8Array, pos: number, end: number): TlvHeader {
  if (pos >= end) throw new DerDecodeError('truncated: expected tag', { offset: pos });
  const start = pos;
  const first = data[pos++];
  const tagClass = first >> 6;
  const constructed = (first & 0x20) !== 0;
  let tagNumber = first & 0x1f;

  if (tagNumber === 0x1f) {
    // High-tag-number form: base-128 tag number in subsequent octets.
    tagNumber = 0;
    let firstSubsequent = true;
    for (;;) {
      if (pos >= end) throw new DerDecodeError('truncated: tag number', { offset: start });
      const b = data[pos++];
      if (firstSubsequent && (b & 0x7f) === 0) {
        throw new DerDecodeError('non-minimal tag number encoding', { offset: start });
      }
      firstSubsequent = false;
      tagNumber = tagNumber * 128 + (b & 0x7f);
      if (!Number.isSafeInteger(tagNumber)) {
        throw new DerDecodeError('tag number too large', { offset: start });
      }
      if ((b & 0x80) === 0) break;
    }
  }

  if (pos >= end) throw new DerDecodeError('truncated: expected length', { offset: start });
  const lengthByte = data[pos++];
  let length: number;
  if (lengthByte < 0x80) {
    length = lengthByte;
  } else {
    const count = lengthByte & 0x7f;
    if (count === 0) throw new DerDecodeError('indefinite length not allowed in DER', { offset: start });
    if (count === 0x7f) throw new DerDecodeError('reserved length form', { offset: start });
    if (count > 8) throw new DerDecodeError('length too large', { offset: start });
    if (pos + count > end) throw new DerDecodeError('truncated: length', { offset: start });
    if (data[pos] === 0) throw new DerDecodeError('non-minimal length encoding', { offset: start });
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + data[pos++];
    if (length < 128) throw new DerDecodeError('non-minimal length encoding', { offset: start });
    if (!Number.isSafeInteger(length)) throw new DerDecodeError('length too large', { offset: start });
  }

  if (length > end - pos) throw new DerDecodeError('truncated: content', { offset: start });
  return { tagClass, constructed, tagNumber, start, headerEnd: pos, end: pos + length, length };
}

/** Stable string key used for tag dispatch tables, e.g. `2:3` for context [3]. */
export function tagKey(tagClass: number, tagNumber: number): string {
  return `${tagClass}:${tagNumber}`;
}

export function describeTag(tagClass: number, tagNumber: number, constructed: boolean): string {
  const cls = (Object.keys(TAG_CLASS) as TagClassName[]).find((k) => TAG_CLASS[k] === tagClass) ?? `${tagClass}`;
  return `${cls} [${tagNumber}]${constructed ? ' constructed' : ''}`;
}
