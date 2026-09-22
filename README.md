# ASN.1 DER core

TypeScript library for DER encoding and decoding.

Run `npm install`, then `npm test` and `npm run build`.

## Schema-driven decoding

`compileSchema` compiles a runtime schema into an executable plan (tag
dispatch tables + field constraints); `decode` runs the plan over a byte
buffer. Every decoded value keeps its original byte range (`span` /
`content`) and its schema path.

```ts
import { compileSchema, decode } from 'asn1-schema-decode-core';

const schema = compileSchema(
  {
    kind: 'sequence',
    fields: [
      { name: 'id', type: { kind: 'integer' } },
      { name: 'name', type: { kind: 'utf8String' } },
      { name: 'active', type: { kind: 'boolean' }, optional: true },
      { name: 'role', type: { kind: 'utf8String' }, default: 'user' },
      { name: 'addr', type: { kind: 'octetString', tag: { number: 0 }, implicit: true } },
      { name: 'cert', type: { kind: 'sequence', fields: [/* ... */], tag: { number: 1 } } }, // [1] EXPLICIT
    ],
  },
  { maxDepth: 64 },
);

const value = decode(schema, bytes);
// value.fields.id.value        -> bigint
// value.fields.id.span         -> { start, end } byte range in `bytes`
// value.defaulted              -> ['role'] when role was absent (DEFAULT applied)
// value.extensions             -> raw spans of unknown trailing TLVs
```

Supported constructs: `sequence`, `set`, `choice`, `sequenceOf`, primitives
(`boolean`, `integer`, `enum`, `octetString`, `bitString`, `null`, `oid`,
`utf8String`), `OPTIONAL`, `DEFAULT`, explicit tags (`tag: { number, class? }`)
and implicit tags (`implicit: true`).

### Compile-time checks

- Tag dispatch for every field is precomputed; an `OPTIONAL`/`DEFAULT` field
  whose tags collide with a later sibling, and `CHOICE` alternatives with
  overlapping tags, are rejected with `SchemaError` (ambiguity is never
  resolved at decode time).
- `DEFAULT` values are type-checked at compile time. An absent `DEFAULT`
  field is synthesized and listed in `defaulted`; an explicitly encoded
  default is decoded from the wire and never appears in `defaulted`.
- `CHOICE` cannot be implicitly tagged; named types are referenced with
  `{ kind: 'ref', name }` via `compileSchema(root, { named })`, which also
  enables recursive schemas. Decoding recursion is bounded by `maxDepth`.

### Errors

`DerDecodeError` carries `schemaPath` (e.g. `$.fields` path such as `$.b`)
and `offset` (byte position in the input) for every failure: missing
required fields, duplicate `SET` members, unexpected tags, truncated input,
and depth-budget exhaustion.
