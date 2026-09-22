import { describe, expect, it } from 'vitest';
import {
  compile,
  decode,
  DerDecodeError,
  SchemaCompileError,
  type CompiledSchema,
  type DecodedValue,
  type SchemaNode,
} from '../src/index.js';

// --- DER byte builders -----------------------------------------------------------

const bytes = (...n: number[]) => Uint8Array.from(n);
const cat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
};
const len = (n: number): Uint8Array => {
  if (n < 128) return bytes(n);
  const parts: number[] = [];
  for (let v = n; v > 0; v >>= 8) parts.unshift(v & 0xff);
  return bytes(0x80 | parts.length, ...parts);
};
const tlv = (tag: number, content: Uint8Array) => cat(bytes(tag), len(content.length), content);
const int = (n: number) => tlv(0x02, bytes(n));
const bool = (v: boolean) => tlv(0x01, bytes(v ? 0xff : 0x00));
const utf8 = (s: string) => tlv(0x0c, new TextEncoder().encode(s));
const seq = (...items: Uint8Array[]) => tlv(0x30, cat(...items));
const set = (...items: Uint8Array[]) => tlv(0x31, cat(...items));
/** Context-specific tag; constructed sets bit 0x20. */
const ctx = (n: number, constructed: boolean, content: Uint8Array) =>
  tlv((constructed ? 0xa0 : 0x80) + n, content);

// --- schema shorthands -----------------------------------------------------

const integer: SchemaNode = { kind: 'integer' };
const booleanT: SchemaNode = { kind: 'boolean' };
const utf8String: SchemaNode = { kind: 'utf8-string' };
const implicit = (number: number, type: SchemaNode): SchemaNode => ({
  kind: 'tagged',
  tag: { class: 'context', number },
  mode: 'implicit',
  type,
});
const explicit = (number: number, type: SchemaNode): SchemaNode => ({
  kind: 'tagged',
  tag: { class: 'context', number },
  mode: 'explicit',
  type,
});

// --- helpers ---------------------------------------------------------------

function field(value: DecodedValue, name: string): DecodedValue {
  if (value.kind !== 'sequence' && value.kind !== 'set') throw new Error(`expected struct, got ${value.kind}`);
  return value.fields[name];
}

function decodeError(fn: () => unknown): DerDecodeError {
  try {
    fn();
  } catch (e) {
    expect(e).toBeInstanceOf(DerDecodeError);
    return e as DerDecodeError;
  }
  throw new Error('expected DerDecodeError');
}

function compileError(fn: () => unknown): SchemaCompileError {
  try {
    fn();
  } catch (e) {
    expect(e).toBeInstanceOf(SchemaCompileError);
    return e as SchemaCompileError;
  }
  throw new Error('expected SchemaCompileError');
}

const fromRoot = (root: SchemaNode, name = 'Root'): CompiledSchema => compile(root, { name });

// --- tests -----------------------------------------------------------------

describe('SEQUENCE', () => {
  const schema = fromRoot({
    kind: 'sequence',
    fields: [
      { name: 'version', type: integer },
      { name: 'name', type: utf8String },
    ],
  });

  it('decodes fields and preserves byte ranges', () => {
    // [30 07 | 02 01 05 | 0c 02 68 69]
    const value = decode(schema, seq(int(5), utf8('hi')));
    expect(value.range).toEqual({ start: 0, end: 9 });
    const version = field(value, 'version');
    expect(version).toMatchObject({ kind: 'integer', value: 5n });
    expect(version.range).toEqual({ start: 2, end: 5 });
    const name = field(value, 'name');
    expect(name).toMatchObject({ kind: 'utf8-string', value: 'hi' });
    expect(name.range).toEqual({ start: 5, end: 9 });
    if (value.kind === 'sequence') {
      expect(value.present).toEqual({ version: true, name: true });
    }
  });

  it('decodes required fields with identical tags positionally', () => {
    const s = fromRoot({
      kind: 'sequence',
      fields: [
        { name: 'a', type: integer },
        { name: 'b', type: integer },
      ],
    });
    const value = decode(s, seq(int(1), int(2)));
    expect(field(value, 'a')).toMatchObject({ value: 1n });
    expect(field(value, 'b')).toMatchObject({ value: 2n });
  });

  it('decodes negative integers (two’s complement)', () => {
    const s = fromRoot({ kind: 'sequence', fields: [{ name: 'n', type: integer }] });
    expect(field(decode(s, seq(tlv(0x02, bytes(0xff)))), 'n')).toMatchObject({ value: -1n });
  });
});

describe('nested and context-specific tags', () => {
  it('decodes nested EXPLICIT tags, range covers the outermost wrapper', () => {
    const schema = fromRoot({
      kind: 'sequence',
      fields: [{ name: 'id', type: explicit(0, explicit(1, integer)) }],
    });
    // [30 07 | a0 05 | a1 03 | 02 01 07]
    const value = decode(schema, seq(ctx(0, true, ctx(1, true, int(7)))));
    const id = field(value, 'id');
    expect(id).toMatchObject({ kind: 'integer', value: 7n });
    expect(id.range).toEqual({ start: 2, end: 9 });
  });

  it('distinguishes the same base type by different context tags (IMPLICIT)', () => {
    const schema = fromRoot({
      kind: 'sequence',
      fields: [
        { name: 'a', type: implicit(0, integer) },
        { name: 'b', type: implicit(1, integer) },
      ],
    });
    // [30 06 | 80 01 03 | 81 01 04]
    const value = decode(schema, seq(ctx(0, false, bytes(3)), ctx(1, false, bytes(4))));
    expect(field(value, 'a')).toMatchObject({ kind: 'integer', value: 3n });
    expect(field(value, 'b')).toMatchObject({ kind: 'integer', value: 4n });
  });

  it('decodes an IMPLICIT-tagged SEQUENCE (constructed context tag)', () => {
    const schema = fromRoot({
      kind: 'sequence',
      fields: [
        {
          name: 't',
          type: implicit(0, { kind: 'sequence', fields: [{ name: 'x', type: integer }] }),
        },
      ],
    });
    // [30 05 | a0 03 | 02 01 09]
    const value = decode(schema, seq(ctx(0, true, int(9))));
    const t = field(value, 't');
    expect(t.kind).toBe('sequence');
    expect(t.range).toEqual({ start: 2, end: 7 });
    expect(field(t, 'x')).toMatchObject({ value: 9n });
  });

  it('decodes high-tag-number form (tag >= 31)', () => {
    const schema = fromRoot({
      kind: 'sequence',
      fields: [{ name: 'big', type: implicit(31, integer) }],
    });
    // context [31] primitive: 9f 1f, length 1, value 5
    const value = decode(schema, seq(cat(bytes(0x9f, 0x1f, 0x01), bytes(5))));
    expect(field(value, 'big')).toMatchObject({ value: 5n });
  });
});

describe('OPTIONAL and DEFAULT', () => {
  const schema = fromRoot({
    kind: 'sequence',
    fields: [
      { name: 'a', type: integer },
      { name: 'flag', type: booleanT, optional: true },
      { name: 'b', type: integer },
    ],
  });

  it('reports an absent OPTIONAL as not present', () => {
    const value = decode(schema, seq(int(1), int(2)));
    if (value.kind !== 'sequence') throw new Error('sequence expected');
    expect(value.present.flag).toBe(false);
    expect(value.fields.flag).toBeUndefined();
    expect(field(value, 'b')).toMatchObject({ value: 2n });
  });

  it('decodes a present OPTIONAL', () => {
    const value = decode(schema, seq(int(1), bool(true), int(2)));
    expect(field(value, 'flag')).toMatchObject({ kind: 'boolean', value: true });
  });

  it('an absent DEFAULT is not the same as an explicitly encoded default value', () => {
    const s = fromRoot({
      kind: 'sequence',
      fields: [
        { name: 'a', type: integer },
        { name: 'version', type: integer, default: 1n },
      ],
    });
    // Absent: default is applied, present === false.
    const absent = decode(s, seq(int(5)));
    if (absent.kind !== 'sequence') throw new Error('sequence expected');
    expect(absent.present.version).toBe(false);
    expect(absent.fields.version).toEqual({ kind: 'default', value: 1n, range: null });
    // Explicitly encoded value equal to the default: present === true.
    const encoded = decode(s, seq(int(5), int(1)));
    if (encoded.kind !== 'sequence') throw new Error('sequence expected');
    expect(encoded.present.version).toBe(true);
    expect(encoded.fields.version).toMatchObject({ kind: 'integer', value: 1n });
  });
});

describe('CHOICE', () => {
  const schema = fromRoot({
    kind: 'sequence',
    fields: [
      {
        name: 'sig',
        type: {
          kind: 'choice',
          alternatives: [
            { name: 'i', type: integer },
            { name: 's', type: utf8String },
          ],
        },
      },
    ],
  });

  it('dispatches alternatives by tag', () => {
    const byInt = field(decode(schema, seq(int(9))), 'sig');
    expect(byInt).toMatchObject({ kind: 'choice', name: 'i' });
    const byStr = field(decode(schema, seq(utf8('x'))), 'sig');
    expect(byStr).toMatchObject({ kind: 'choice', name: 's' });
  });

  it('rejects input matching no alternative', () => {
    // Inside a SEQUENCE, a non-matching required CHOICE surfaces as a missing field…
    const err = decodeError(() => decode(schema, seq(bool(true))));
    expect(err.message).toMatch(/missing required field 'sig'/);
    expect(err.path).toBe('Root.sig');
    expect(err.offset).toBe(2);
    // …and at the top level the CHOICE itself reports no matching alternative.
    const choiceSchema = fromRoot(
      {
        kind: 'choice',
        alternatives: [
          { name: 'i', type: integer },
          { name: 's', type: utf8String },
        ],
      },
      'Sig',
    );
    const rootErr = decodeError(() => decode(choiceSchema, bool(true)));
    expect(rootErr.message).toMatch(/no CHOICE alternative/);
    expect(rootErr.path).toBe('Sig');
    expect(rootErr.offset).toBe(0);
  });
});

describe('SEQUENCE OF', () => {
  const schema = fromRoot({ kind: 'sequence-of', element: integer }, 'Ints');

  it('decodes elements with indices in the path', () => {
    const value = decode(schema, seq(int(1), int(2), int(3)));
    if (value.kind !== 'sequence-of') throw new Error('sequence-of expected');
    expect(value.items.map((i) => (i.kind === 'integer' ? i.value : null))).toEqual([1n, 2n, 3n]);
    expect(value.items[1].range).toEqual({ start: 5, end: 8 });
  });

  it('decodes the empty sequence', () => {
    const value = decode(schema, bytes(0x30, 0x00));
    expect(value).toMatchObject({ kind: 'sequence-of', items: [] });
  });

  it('reports element errors with index path and offset', () => {
    const err = decodeError(() => decode(schema, seq(int(1), bool(true))));
    expect(err.path).toBe('Ints[1]');
    expect(err.offset).toBe(5);
  });
});

describe('SET', () => {
  const schema = fromRoot(
    {
      kind: 'set',
      fields: [
        { name: 'a', type: implicit(0, integer) },
        { name: 'b', type: implicit(1, integer) },
      ],
    },
    'S',
  );

  it('dispatches members by tag regardless of order', () => {
    const value = decode(schema, set(ctx(1, false, bytes(4)), ctx(0, false, bytes(3))));
    expect(field(value, 'a')).toMatchObject({ value: 3n });
    expect(field(value, 'b')).toMatchObject({ value: 4n });
  });

  it('rejects duplicate members with path and offset', () => {
    const dup = fromRoot({
      kind: 'set',
      fields: [
        { name: 'a', type: integer },
        { name: 'b', type: booleanT },
      ],
    });
    // [31 06 | 02 01 01 | 02 01 02] — second INTEGER duplicates 'a'
    const err = decodeError(() => decode(dup, set(int(1), int(2))));
    expect(err.message).toMatch(/duplicate SET member 'a'/);
    expect(err.path).toBe('Root.a');
    expect(err.offset).toBe(5);
  });

  it('rejects a missing required member', () => {
    const err = decodeError(() => decode(schema, set(ctx(0, false, bytes(3)))));
    expect(err.message).toMatch(/missing required SET member 'b'/);
    expect(err.path).toBe('S.b');
  });
});

describe('unknown extension fields', () => {
  const root: SchemaNode = { kind: 'sequence', fields: [{ name: 'a', type: integer }] };

  it('rejects unknown trailing fields when not extensible', () => {
    const err = decodeError(() => decode(fromRoot(root), seq(int(1), bool(true))));
    expect(err.message).toMatch(/unknown extension field/);
    expect(err.offset).toBe(5);
  });

  it('captures unknown fields as raw extensions when extensible', () => {
    const s = fromRoot({ kind: 'sequence', fields: [{ name: 'a', type: integer }], extensible: true });
    const value = decode(s, seq(int(1), bool(true)));
    if (value.kind !== 'sequence') throw new Error('sequence expected');
    expect(value.extensions).toHaveLength(1);
    expect(value.extensions[0]).toMatchObject({ tagClass: 0, tagNumber: 1, range: { start: 5, end: 8 } });
    expect(value.extensions[0].raw).toEqual(bool(true));
  });
});

describe('missing required fields', () => {
  const schema = fromRoot({
    kind: 'sequence',
    fields: [
      { name: 'a', type: integer },
      { name: 'b', type: integer },
    ],
  });

  it('reports a truncated-away field at end of content', () => {
    const err = decodeError(() => decode(schema, seq(int(1))));
    expect(err.message).toMatch(/missing required field 'b'/);
    expect(err.path).toBe('Root.b');
    expect(err.offset).toBe(5);
  });

  it('reports an unexpected tag in place of a required field', () => {
    const err = decodeError(() => decode(schema, seq(bool(false))));
    expect(err.message).toMatch(/missing required field 'a'/);
    expect(err.path).toBe('Root.a');
    expect(err.offset).toBe(2);
  });

  it('builds nested schema paths', () => {
    const cert = compile(
      {
        kind: 'sequence',
        fields: [
          {
            name: 'tbs',
            type: { kind: 'sequence', fields: [{ name: 'version', type: integer }] },
          },
        ],
      },
      { name: 'Cert' },
    );
    const err = decodeError(() => decode(cert, seq(seq(bool(false)))));
    expect(err.path).toBe('Cert.tbs.version');
    expect(err.offset).toBe(4);
  });
});

describe('compile-time ambiguity detection', () => {
  it('rejects an OPTIONAL field indistinguishable from the next field', () => {
    const err = compileError(() =>
      compile({
        kind: 'sequence',
        fields: [
          { name: 'a', type: integer, optional: true },
          { name: 'b', type: integer },
        ],
      }),
    );
    expect(err.message).toMatch(/ambiguous: OPTIONAL field 'a'.*field 'b'/);
  });

  it('rejects a DEFAULT field indistinguishable from a later OPTIONAL', () => {
    const err = compileError(() =>
      compile({
        kind: 'sequence',
        fields: [
          { name: 'a', type: integer, default: 0n },
          { name: 'b', type: integer, optional: true },
        ],
      }),
    );
    expect(err.message).toMatch(/ambiguous: DEFAULT field 'a'/);
  });

  it('rejects overlapping CHOICE alternatives', () => {
    const err = compileError(() =>
      compile({
        kind: 'choice',
        alternatives: [
          { name: 'x', type: integer },
          { name: 'y', type: integer },
        ],
      }),
    );
    expect(err.message).toMatch(/ambiguous: CHOICE alternatives 'x' and 'y'/);
  });

  it('rejects overlapping SET members', () => {
    const err = compileError(() =>
      compile({
        kind: 'set',
        fields: [
          { name: 'a', type: integer },
          { name: 'b', type: integer },
        ],
      }),
    );
    expect(err.message).toMatch(/ambiguous: SET members 'a' and 'b'/);
  });

  it('rejects IMPLICIT tagging of CHOICE', () => {
    expect(
      compileError(() =>
        compile(implicit(0, { kind: 'choice', alternatives: [{ name: 'i', type: integer }] })),
      ).message,
    ).toMatch(/IMPLICIT tagging cannot be applied to CHOICE/);
  });

  it('rejects unknown references, bad defaults and duplicate names', () => {
    expect(compileError(() => compile({ kind: 'ref', name: 'Nope' })).message).toMatch(
      /unknown type reference 'Nope'/,
    );
    expect(
      compileError(() =>
        compile({ kind: 'sequence', fields: [{ name: 'a', type: integer, default: 'x' }] }),
      ).message,
    ).toMatch(/DEFAULT value does not match/);
    expect(
      compileError(() =>
        compile({
          kind: 'sequence',
          fields: [
            { name: 'a', type: integer },
            { name: 'a', type: integer },
          ],
        }),
      ).message,
    ).toMatch(/duplicate field name 'a'/);
    expect(
      compileError(() =>
        compile({
          kind: 'sequence',
          fields: [{ name: 'a', type: integer, optional: true, default: 0n }],
        }),
      ).message,
    ).toMatch(/cannot be both OPTIONAL and DEFAULT/);
  });
});

describe('recursive schemas', () => {
  const types: Record<string, SchemaNode> = {
    Node: {
      kind: 'sequence',
      fields: [
        { name: 'value', type: integer },
        { name: 'next', type: { kind: 'ref', name: 'Node' }, optional: true },
      ],
    },
  };
  const schema = compile({ kind: 'ref', name: 'Node' }, { types, name: 'Node' });

  it('decodes recursive values through named references', () => {
    const value = decode(schema, seq(int(1), seq(int(2), seq(int(3)))));
    const level2 = field(value, 'next');
    const level3 = field(level2, 'next');
    expect(field(value, 'value')).toMatchObject({ value: 1n });
    expect(field(level2, 'value')).toMatchObject({ value: 2n });
    expect(field(level3, 'value')).toMatchObject({ value: 3n });
    if (level3.kind === 'sequence') expect(level3.present.next).toBe(false);
  });

  it('enforces the recursion depth budget', () => {
    const input = seq(int(1), seq(int(2), seq(int(3))));
    const err = decodeError(() => decode(schema, input, { maxDepth: 2 }));
    expect(err.message).toMatch(/recursion depth budget exceeded at type 'Node'/);
    expect(err.path).toContain('Node');
    expect(err.offset).toBeGreaterThan(0);
  });

  it('rejects recursion that can never terminate', () => {
    const err = compileError(() =>
      compile(
        { kind: 'ref', name: 'A' },
        { types: { A: { kind: 'sequence', fields: [{ name: 'next', type: { kind: 'ref', name: 'A' } }] } } },
      ),
    );
    expect(err.message).toMatch(/unproductive recursion: type 'A'/);
  });

  it('allows recursion through SEQUENCE OF (empty terminates)', () => {
    const s = compile(
      { kind: 'ref', name: 'Tree' },
      {
        types: {
          Tree: {
            kind: 'sequence',
            fields: [
              { name: 'label', type: integer },
              { name: 'children', type: { kind: 'sequence-of', element: { kind: 'ref', name: 'Tree' } } },
            ],
          },
        },
      },
    );
    const leaf = seq(int(7), bytes(0x30, 0x00));
    const value = decode(s, seq(int(1), seq(leaf, leaf)));
    const children = field(value, 'children');
    if (children.kind !== 'sequence-of') throw new Error('sequence-of expected');
    expect(children.items).toHaveLength(2);
    expect(field(children.items[0], 'label')).toMatchObject({ value: 7n });
  });
});

describe('truncated and malformed input', () => {
  const schema = fromRoot({ kind: 'sequence', fields: [{ name: 'a', type: integer }] });

  it('rejects empty input and truncated headers', () => {
    expect(decodeError(() => decode(schema, bytes())).message).toMatch(/truncated/);
    expect(decodeError(() => decode(schema, bytes(0x30))).message).toMatch(/truncated/);
    expect(decodeError(() => decode(schema, bytes(0x1f))).message).toMatch(/truncated: tag number/);
  });

  it('rejects truncated content at top level and nested', () => {
    const top = decodeError(() => decode(schema, bytes(0x30, 0x05, 0x02, 0x01, 0x01)));
    expect(top.message).toMatch(/truncated: content/);
    expect(top.offset).toBe(0);
    // Inner INTEGER declares length 3 but only 2 bytes remain in the outer content.
    const nested = decodeError(() => decode(schema, bytes(0x30, 0x04, 0x02, 0x03, 0x05, 0x06)));
    expect(nested.message).toMatch(/truncated: content/);
    expect(nested.offset).toBe(2);
  });

  it('rejects trailing data after the top-level value', () => {
    const err = decodeError(() => decode(schema, cat(seq(int(1)), bytes(0x00))));
    expect(err.message).toMatch(/trailing data/);
    expect(err.offset).toBe(5);
  });

  it('enforces DER length and integer strictness', () => {
    expect(decodeError(() => decode(schema, bytes(0x30, 0x80, 0x00, 0x00))).message).toMatch(
      /indefinite length/,
    );
    expect(decodeError(() => decode(schema, bytes(0x30, 0x03, 0x02, 0x81, 0x01, 0x05))).message).toMatch(
      /non-minimal length/,
    );
    expect(decodeError(() => decode(schema, seq(tlv(0x02, bytes(0x00, 0x05))))).message).toMatch(
      /non-minimal INTEGER/,
    );
    expect(decodeError(() => decode(schema, seq(tlv(0x02, bytes())))).message).toMatch(/empty INTEGER/);
  });

  it('decodes long-form lengths', () => {
    const s = fromRoot({ kind: 'sequence', fields: [{ name: 'blob', type: { kind: 'octet-string' } }] });
    const content = new Uint8Array(200).fill(7);
    const value = decode(s, seq(cat(bytes(0x04, 0x81, 0xc8), content)));
    expect(field(value, 'blob')).toMatchObject({ kind: 'octet-string' });
    expect((field(value, 'blob') as { value: Uint8Array }).value).toHaveLength(200);
  });
});

describe('primitive types', () => {
  it('decodes BOOLEAN, NULL, OID and enforces DER rules', () => {
    const s = fromRoot({
      kind: 'sequence',
      fields: [
        { name: 'flag', type: booleanT },
        { name: 'nothing', type: { kind: 'null' } },
        { name: 'oid', type: { kind: 'oid' } },
      ],
    });
    const value = decode(s, seq(bool(true), bytes(0x05, 0x00), tlv(0x06, bytes(0x2b, 0x06, 0x01))));
    expect(field(value, 'flag')).toMatchObject({ value: true });
    expect(field(value, 'nothing')).toMatchObject({ value: null });
    expect(field(value, 'oid')).toMatchObject({ value: '1.3.6.1' });

    const badBool = fromRoot({ kind: 'sequence', fields: [{ name: 'b', type: booleanT }] });
    expect(decodeError(() => decode(badBool, seq(tlv(0x01, bytes(0x7f))))).message).toMatch(/BOOLEAN/);
  });
});
