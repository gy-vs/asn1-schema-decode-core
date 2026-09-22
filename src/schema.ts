import type { TagClassName } from './tlv.js';

/** A tag applied to a schema node, e.g. `{ class: 'context', number: 0 }` for `[0]`. */
export interface TagSpec {
  class: TagClassName;
  number: number;
}

/** A field of a SEQUENCE or SET. */
export interface FieldDef {
  name: string;
  type: SchemaNode;
  /** ASN.1 OPTIONAL: the field may be absent from the encoding. */
  optional?: boolean;
  /**
   * ASN.1 DEFAULT: when absent, this value is used. An absent DEFAULT field is
   * reported as not present — it is not the same as an explicitly encoded
   * value that happens to equal the default.
   */
  default?: unknown;
}

export interface AlternativeDef {
  name: string;
  type: SchemaNode;
}

/**
 * Runtime schema description. Compile with `compile()` before decoding.
 *
 * - `tagged` applies an EXPLICIT or IMPLICIT tag to any node.
 * - `ref` refers to a named type passed via `CompileOptions.types`; this is
 *   the only way to build recursive schemas, and recursion depth is bounded
 *   by a decode-time budget.
 */
export type SchemaNode =
  | { kind: 'boolean' }
  | { kind: 'integer' }
  | { kind: 'octet-string' }
  | { kind: 'null' }
  | { kind: 'oid' }
  | { kind: 'utf8-string' }
  | { kind: 'any' }
  | { kind: 'sequence'; fields: FieldDef[]; extensible?: boolean }
  | { kind: 'set'; fields: FieldDef[]; extensible?: boolean }
  | { kind: 'sequence-of'; element: SchemaNode }
  | { kind: 'choice'; alternatives: AlternativeDef[] }
  | { kind: 'tagged'; tag: TagSpec; mode: 'explicit' | 'implicit'; type: SchemaNode }
  | { kind: 'ref'; name: string };

export interface CompileOptions {
  /** Named types that `ref` nodes resolve against. */
  types?: Record<string, SchemaNode>;
  /** Name of the root type, used as the root of error paths. Defaults to '$'. */
  name?: string;
}
