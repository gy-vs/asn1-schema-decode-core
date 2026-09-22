import { describe, expect, it } from 'vitest';
import {
  ChoiceValue,
  compileSchema,
  decode,
  DerDecodeError,
  IntegerValue,
  SchemaError,
  SchemaNode,
  SequenceValue,
} from '../src/index.js';

// --- minimal DER encoder for fixtures -------------------------------------

const concat = (...parts: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
};

const tlv = (tag: number, content: Uint8Array): Uint8Array => {
  const len = content.length;
  const lenBytes = len < 0x80 ? [len] : [0x81, len];
  return Uint8Array.from([tag, ...lenBytes, ...content]);
};

const intBytes = (n: number): Uint8Array => {
  const bytes: number[] = [];
  let v = n;
  do {
    bytes.unshift(v & 0xff);
    v >>= 8;
  } while (v > 0);
  if (bytes[0] & 0x80) bytes.unshift(0);
  return Uint8Array.from(bytes);
};

const derInt = (n: number) => tlv(0x02, intBytes(n));
const derBool = (b: boolean) => tlv(0x01, Uint8Array.of(b ? 0xff : 0x00));
const derUtf8 = (s: string) => tlv(0x0c, new TextEncoder().encode(s));
const derOcts = (b: number[]) => tlv(0x04, Uint8Array.from(b));
const derSeq = (...items: Uint8Array[]) => tlv(0x30, concat(...items));
const derSet = (...items: Uint8Array[]) => tlv(0x31, concat(...items));
/** [n] EXPLICIT wrapper (context, constructed). */
const derExplicit = (n: number, inner: Uint8Array) => tlv(0xa0 + n, inner);
/** [n] IMPLICIT retag (context; constructed bit by caller). */
const derImplicit = (n: number, content: Uint8Array, constructed = false) =>
  tlv((constructed ? 0xa0 : 0x80) + n, content);

const asSeq = (v: unknown) => v as SequenceValue;
const asInt = (v: unknown) => (v as IntegerValue).value;

// --- SEQUENCE / OPTIONAL / DEFAULT -----------------------------------------

describe('sequence with optional and default', () => {
  const schema = compileSchema({
    kind: 'sequence',
    fields: [
      { name: 'id', type: { kind: 'integer' } },
      { name: 'name', type: { kind: 'utf8String' } },
      { name: 'active', type: { kind: 'boolean' }, optional: true },
      { name: 'role', type: { kind: 'utf8String' }, default: 'user' },
    ],
  });

  it('decodes present members and keeps original spans', () => {
    const bytes = derSeq(derInt(7), derUtf8('ada'), derBool(true), derUtf8('admin'));
    const root = asSeq(decode(schema, bytes));
    expect(root.span).toEqual({ start: 0, end: bytes.length });
    expect(asInt(root.fields.id)).toBe(7n);
    expect(root.fields.id.span).toEqual({ start: 2, end: 5 }); // 30 1a | 02 01 07
    expect(root.fields.name.kind).toBe('utf8String');
    expect((root.fields.active as { value: boolean }).value).toBe(true);
    expect(root.defaulted).toEqual([]);
    expect(root.extensions).toEqual([]);
  });

  it('fills an absent DEFAULT and records it as defaulted', () => {
    const root = asSeq(decode(schema, derSeq(derInt(7), derUtf8('ada'))));
    expect(root.fields.role).toMatchObject({ kind: 'utf8String', value: 'user' });
    expect(root.defaulted).toEqual(['role']);
    expect(root.fields.active).toBeUndefined();
  });

  it('treats an explicitly encoded default as present on the wire', () => {
    const root = asSeq(decode(schema, derSeq(derInt(7), derUtf8('ada'), derUtf8('user'))));
    expect(root.fields.role).toMatchObject({ value: 'user' });
    expect(root.defaulted).toEqual([]); // not synthesized: it arrived on the wire
  });

  it('collects unknown trailing extension fields as raw spans', () => {
    const ext = tlv(0x89, Uint8Array.of(1, 2, 3)); // context 9, unknown to schema
    const bytes = derSeq(derInt(7), derUtf8('ada'), ext);
    const root = asSeq(decode(schema, bytes));
    expect(root.extensions).toHaveLength(1);
    const [span] = root.extensions;
    expect(bytes.slice(span.start, span.end)).toEqual(ext);
  });

  it('rejects trailing bytes after the root value', () => {
    const bytes = concat(derSeq(derInt(7), derUtf8('ada')), Uint8Array.of(0));
    expect(() => decode(schema, bytes)).toThrowError(/trailing bytes/);
  });
});

// --- nested explicit tags ----------------------------------------------------

describe('nested explicit tags', () => {
  const schema = compileSchema({
    kind: 'sequence',
    fields: [
      { name: 'a', type: { kind: 'integer', tag: { number: 0 } } },
      {
        name: 'b',
        type: {
          kind: 'sequence',
          fields: [{ name: 'x', type: { kind: 'boolean' } }],
          tag: { number: 1 },
        },
      },
    ],
  });

  it('unwraps [0] EXPLICIT INTEGER and [1] EXPLICIT SEQUENCE', () => {
    const bytes = derSeq(derExplicit(0, derInt(5)), derExplicit(1, derSeq(derBool(true))));
    const root = asSeq(decode(schema, bytes));
    expect(asInt(root.fields.a)).toBe(5n);
    expect(asSeq(root.fields.b).fields.x).toMatchObject({ value: true });
  });

  it('rejects a wrongly tagged wrapper with path and offset', () => {
    const bytes = derSeq(derExplicit(2, derInt(5)), derExplicit(1, derSeq(derBool(true))));
    const err = catchErr(() => decode(schema, bytes));
    expect(err).toBeInstanceOf(DerDecodeError);
    expect(err!.schemaPath).toBe('$.a');
    expect(err!.offset).toBe(2);
  });
});

// --- same base type, different context tags ----------------------------------

describe('same base type under different context tags', () => {
  const schema = compileSchema({
    kind: 'sequence',
    fields: [
      { name: 'v4', type: { kind: 'octetString', tag: { number: 0 }, implicit: true } },
      { name: 'v6', type: { kind: 'octetString', tag: { number: 1 }, implicit: true } },
      { name: 'gateway', type: { kind: 'octetString', tag: { number: 2 } } }, // explicit
    ],
  });

  it('dispatches by context tag, not by base type', () => {
    const bytes = derSeq(
      derImplicit(0, Uint8Array.of(192, 168, 0, 1)),
      derImplicit(1, Uint8Array.from({ length: 16 }, (_, i) => i)),
      derExplicit(2, derOcts([10, 0, 0, 1])),
    );
    const root = asSeq(decode(schema, bytes));
    expect([...(root.fields.v4 as { value: Uint8Array }).value]).toEqual([192, 168, 0, 1]);
    expect((root.fields.v6 as { value: Uint8Array }).value).toHaveLength(16);
    expect([...(root.fields.gateway as { value: Uint8Array }).value]).toEqual([10, 0, 0, 1]);
  });
});

// --- CHOICE -------------------------------------------------------------------

describe('choice', () => {
  const schema = compileSchema({
    kind: 'sequence',
    fields: [
      {
        name: 'sel',
        type: {
          kind: 'choice',
          alternatives: [
            { kind: 'integer' },
            { kind: 'utf8String' },
            { kind: 'octetString', tag: { number: 3 }, implicit: true },
          ],
        },
      },
    ],
  });

  it('selects alternatives by tag dispatch', () => {
    const byInt = asSeq(decode(schema, derSeq(derInt(9))));
    expect((byInt.fields.sel as ChoiceValue).alternative).toBe(0);
    expect(asInt((byInt.fields.sel as ChoiceValue).value)).toBe(9n);

    const byStr = asSeq(decode(schema, derSeq(derUtf8('hi'))));
    expect((byStr.fields.sel as ChoiceValue).alternative).toBe(1);

    const byTagged = asSeq(decode(schema, derSeq(derImplicit(3, Uint8Array.of(1)))));
    expect((byTagged.fields.sel as ChoiceValue).alternative).toBe(2);
  });

  it('fails with path and offset when no alternative matches', () => {
    const err = catchErr(() => decode(schema, derSeq(derBool(true))));
    expect(err).toBeInstanceOf(DerDecodeError);
    expect(err!.schemaPath).toBe('$.sel');
    expect(err!.offset).toBe(2);
  });

  it('supports an explicitly tagged choice', () => {
    const explicitChoice = compileSchema({
      kind: 'choice',
      tag: { number: 5 },
      alternatives: [{ kind: 'integer' }, { kind: 'utf8String' }],
    });
    const v = decode(explicitChoice, derExplicit(5, derInt(3))) as ChoiceValue;
    expect(v.alternative).toBe(0);
    expect(asInt(v.value)).toBe(3n);
  });
});

// --- SEQUENCE OF ----------------------------------------------------------------

describe('sequence of', () => {
  it('decodes a homogeneous list', () => {
    const schema = compileSchema({ kind: 'sequenceOf', element: { kind: 'integer' } });
    const v = decode(schema, derSeq(derInt(1), derInt(2), derInt(300)));
    expect(v.kind).toBe('sequenceOf');
    expect((v as { items: IntegerValue[] }).items.map((i) => i.value)).toEqual([1n, 2n, 300n]);
  });

  it('decodes a sequence of sequences', () => {
    const schema = compileSchema({
      kind: 'sequenceOf',
      element: { kind: 'sequence', fields: [{ name: 'n', type: { kind: 'integer' } }] },
    });
    const v = decode(schema, derSeq(derSeq(derInt(1)), derSeq(derInt(2))));
    expect((v as { items: SequenceValue[] }).items.map((s) => asInt(s.fields.n))).toEqual([1n, 2n]);
  });
});

// --- SET ------------------------------------------------------------------------

describe('set', () => {
  const schema = compileSchema({
    kind: 'set',
    fields: [
      { name: 'a', type: { kind: 'integer' } },
      { name: 'b', type: { kind: 'utf8String' } },
      { name: 'c', type: { kind: 'boolean' }, optional: true },
    ],
  });

  it('accepts members in any order', () => {
    const root = asSeq(decode(schema, derSet(derUtf8('x'), derInt(1))));
    expect(asInt(root.fields.a)).toBe(1n);
    expect(root.fields.b).toMatchObject({ value: 'x' });
  });

  it('rejects a duplicate member with path and offset', () => {
    const bytes = derSet(derInt(1), derUtf8('x'), derInt(2));
    const err = catchErr(() => decode(schema, bytes));
    expect(err).toBeInstanceOf(DerDecodeError);
    expect(err!.message).toMatch(/duplicate SET member "a"/);
    expect(err!.schemaPath).toBe('$.a');
    expect(err!.offset).toBe(8); // third TLV starts after 31 09 02 01 01 0c 01 78
  });

  it('rejects an unknown member', () => {
    const err = catchErr(() => decode(schema, derSet(derInt(1), derOcts([9]))));
    expect(err!.message).toMatch(/unexpected SET member/);
  });

  it('rejects a missing required member', () => {
    const err = catchErr(() => decode(schema, derSet(derInt(1))));
    expect(err!.schemaPath).toBe('$.b');
    expect(err!.message).toMatch(/missing required field "b"/);
  });
});

// --- missing required / wrong tag ------------------------------------------------

describe('constraint violations', () => {
  const schema = compileSchema({
    kind: 'sequence',
    fields: [
      { name: 'a', type: { kind: 'integer' } },
      { name: 'b', type: { kind: 'utf8String' } },
    ],
  });

  it('reports schema path and byte offset for a missing required field', () => {
    const bytes = derSeq(derInt(1));
    const err = catchErr(() => decode(schema, bytes));
    expect(err).toBeInstanceOf(DerDecodeError);
    expect(err!.schemaPath).toBe('$.b');
    expect(err!.offset).toBe(5); // end of content
  });

  it('reports a wrong wire tag with the field offset', () => {
    const bytes = derSeq(derBool(true), derUtf8('x'));
    const err = catchErr(() => decode(schema, bytes));
    expect(err!.schemaPath).toBe('$.a');
    expect(err!.offset).toBe(2);
  });
});

// --- recursion and depth budget ---------------------------------------------------

describe('recursive schema via named refs', () => {
  const named: Record<string, SchemaNode> = {
    Node: {
      kind: 'sequence',
      fields: [
        { name: 'value', type: { kind: 'integer' } },
        { name: 'next', type: { kind: 'ref', name: 'Node', tag: { number: 0 } }, optional: true },
      ],
    },
  };

  const encodeList = (values: number[]): Uint8Array => {
    let inner: Uint8Array | undefined;
    for (let i = values.length - 1; i >= 0; i--) {
      inner = derSeq(derInt(values[i]), ...(inner ? [derExplicit(0, inner)] : []));
    }
    return inner!;
  };

  it('decodes a recursive linked list', () => {
    const schema = compileSchema({ kind: 'ref', name: 'Node' }, { named });
    const root = asSeq(decode(schema, encodeList([1, 2, 3])));
    expect(asInt(root.fields.value)).toBe(1n);
    const second = asSeq(root.fields.next);
    expect(asInt(second.fields.value)).toBe(2n);
    const third = asSeq(second.fields.next);
    expect(asInt(third.fields.value)).toBe(3n);
    expect(third.fields.next).toBeUndefined();
  });

  it('enforces the depth budget', () => {
    const schema = compileSchema({ kind: 'ref', name: 'Node' }, { named, maxDepth: 4 });
    const err = catchErr(() => decode(schema, encodeList([1, 2, 3, 4, 5, 6])));
    expect(err).toBeInstanceOf(DerDecodeError);
    expect(err!.message).toMatch(/depth budget/);
    expect(err!.schemaPath).toContain('Node');
  });

  it('rejects an unknown named type at compile time', () => {
    expect(() => compileSchema({ kind: 'ref', name: 'Nope' })).toThrowError(SchemaError);
  });
});

// --- truncated input ---------------------------------------------------------------

describe('truncated input', () => {
  const schema = compileSchema({
    kind: 'sequence',
    fields: [
      { name: 'a', type: { kind: 'integer' } },
      { name: 'b', type: { kind: 'integer' } },
    ],
  });

  it('reports a truncated header at offset 0', () => {
    const err = catchErr(() => decode(schema, Uint8Array.of(0x30)));
    expect(err).toBeInstanceOf(DerDecodeError);
    expect(err!.offset).toBe(0);
  });

  it('reports content shorter than the declared length', () => {
    const err = catchErr(() => decode(schema, Uint8Array.of(0x30, 0x06, 0x02, 0x01, 0x01)));
    expect(err!.offset).toBe(0);
    expect(err!.message).toMatch(/truncated content/);
  });

  it('reports a truncated member inside a sequence with the member offset', () => {
    // SEQUENCE(len 4) { INTEGER 1, <lone tag 0x02> }
    const err = catchErr(() => decode(schema, Uint8Array.of(0x30, 0x04, 0x02, 0x01, 0x01, 0x02)));
    expect(err).toBeInstanceOf(DerDecodeError);
    expect(err!.schemaPath).toBe('$');
    expect(err!.offset).toBe(5);
  });
  it('rejects a primitive encoding of a constructed type', () => {
    const schema = compileSchema({
      kind: 'sequence',
      fields: [{ name: 's', type: { kind: 'sequenceOf', element: { kind: 'integer' } } }],
    });
    // context? no: universal 16 with the constructed bit cleared
    const err = catchErr(() => decode(schema, derSeq(tlv(0x10, Uint8Array.of(2, 1, 5)))));
    expect(err).toBeInstanceOf(DerDecodeError);
    expect(err!.schemaPath).toBe('$.s');
    expect(err!.offset).toBe(2);
  });
});

// --- compile-time ambiguity detection ----------------------------------------------

describe('compile-time ambiguity detection', () => {
  it('rejects an OPTIONAL field shadowing a same-tag successor', () => {
    expect(() =>
      compileSchema({
        kind: 'sequence',
        fields: [
          { name: 'a', type: { kind: 'integer' }, optional: true },
          { name: 'b', type: { kind: 'integer' } },
        ],
      }),
    ).toThrowError(/ambiguous tag/);
  });

  it('rejects CHOICE alternatives with overlapping tags', () => {
    expect(() =>
      compileSchema({
        kind: 'choice',
        alternatives: [{ kind: 'integer' }, { kind: 'enum' }],
      }),
    ).toThrowError(/ambiguous CHOICE/);
  });

  it('rejects an untagged CHOICE field colliding with a sibling', () => {
    expect(() =>
      compileSchema({
        kind: 'sequence',
        fields: [
          {
            name: 'c',
            type: { kind: 'choice', alternatives: [{ kind: 'integer' }, { kind: 'utf8String' }] },
            optional: true,
          },
          { name: 'n', type: { kind: 'integer' } },
        ],
      }),
    ).toThrowError(/ambiguous tag/);
  });

  it('rejects an implicitly tagged CHOICE', () => {
    expect(() =>
      compileSchema({
        kind: 'choice',
        tag: { number: 1 },
        implicit: true,
        alternatives: [{ kind: 'integer' }],
      }),
    ).toThrowError(/cannot be implicitly tagged/);
  });

  it('rejects a DEFAULT of the wrong type', () => {
    expect(() =>
      compileSchema({
        kind: 'sequence',
        fields: [{ name: 'x', type: { kind: 'integer' }, default: 'foo' }],
      }),
    ).toThrowError(/DEFAULT must be a number/);
  });

  it('rejects a field that is both OPTIONAL and DEFAULT', () => {
    expect(() =>
      compileSchema({
        kind: 'sequence',
        fields: [{ name: 'x', type: { kind: 'boolean' }, optional: true, default: true }],
      }),
    ).toThrowError(/both OPTIONAL and DEFAULT/);
  });
});

const catchErr = (fn: () => unknown): DerDecodeError | undefined => {
  try {
    fn();
    return undefined;
  } catch (e) {
    return e as DerDecodeError;
  }
};
