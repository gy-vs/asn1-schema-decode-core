# ASN.1 DER core

TypeScript library for DER encoding and decoding.

Run `npm install`, then `npm test` and `npm run build`.

## Runtime-schema decoder

`compile()` turns a runtime schema into a compiled decoder plan (tag dispatch
tables + field constraints); `decode()` applies it to DER bytes and returns a
value tree in which every node keeps its original byte range.

```ts
import { compile, decode } from 'asn1-schema-decode-core';

const schema = compile(
  {
    kind: 'sequence',
    fields: [
      { name: 'version', type: { kind: 'integer' }, default: 0n },
      { name: 'name', type: { kind: 'utf8-string' } },
      { name: 'email', type: { kind: 'utf8-string' }, optional: true },
      { name: 'key', type: { kind: 'tagged', tag: { class: 'context', number: 0 }, mode: 'explicit', type: { kind: 'octet-string' } } },
    ],
  },
  { name: 'Identity' },
);

const value = decode(schema, derBytes);
// value.kind === 'sequence'
// value.fields.name        → { kind: 'utf8-string', value: '...', range: { start, end } }
// value.present.version    → false when the DEFAULT was not encoded
// value.fields.email       → undefined when the OPTIONAL was absent
```

Supported schema nodes: `boolean`, `integer` (→ `bigint`), `octet-string`,
`utf8-string`, `null`, `oid`, `any`, `sequence`, `set`, `sequence-of`,
`choice`, `tagged` (explicit/implicit, arbitrarily nested), and `ref` for
named references.

### Semantics

- **Compile-time checks.** Schemas that cannot be decoded unambiguously are
  rejected by `compile` with a `SchemaCompileError`: an OPTIONAL/DEFAULT field
  whose tag overlaps a following field, overlapping CHOICE alternatives or SET
  members, IMPLICIT tagging of CHOICE/ANY, unknown references, and recursive
  cycles that can never terminate.
- **OPTIONAL vs DEFAULT.** For every field, `present[name]` records whether it
  was actually encoded. An absent DEFAULT is filled in as
  `{ kind: 'default', value, range: null }` — never confused with an
  explicitly encoded value equal to the default.
- **Recursion.** Recursive schemas are expressed with named references
  (`{ kind: 'ref', name }` + `compile(root, { types })`) and decoded under a
  depth budget (`decode(schema, data, { maxDepth })`, default 64).
- **Extensions.** `sequence`/`set` nodes with `extensible: true` capture
  unknown fields as raw TLVs in `extensions`; otherwise unknown fields are an
  error.
- **Errors.** `DerDecodeError` carries the schema `path`
  (e.g. `Cert.tbs.subject[2]`) and the byte `offset` of the offending TLV.
- **DER strictness.** Indefinite lengths, non-minimal length/tag/INTEGER
  encodings and malformed BOOLEAN/NULL/OID values are rejected. SET member
  order is *not* enforced (members are dispatched by tag).

## Legacy low-level API

`decodeTlv` and `decodeInteger` are kept for backwards compatibility;
`readTlv` is the DER-strict low-level reader used by the decoder.
