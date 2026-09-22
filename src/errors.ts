/** Base error carrying the schema path and byte offset of the failure. */
export class DerError extends Error {
  /** Byte offset into the input where the problem was detected, or -1 when not applicable. */
  readonly offset: number;
  /** Dotted schema path, e.g. `Certificate.tbsCertificate.subject`. */
  readonly path: string;

  constructor(message: string, options: { offset?: number; path?: string } = {}) {
    const where = [
      options.path ? `at ${options.path}` : '',
      options.offset !== undefined ? `offset ${options.offset}` : '',
    ]
      .filter(Boolean)
      .join(', ');
    super(where ? `${message} (${where})` : message);
    this.name = new.target.name;
    this.offset = options.offset ?? -1;
    this.path = options.path ?? '';
  }
}

/** Raised when the input bytes cannot be decoded against the compiled schema. */
export class DerDecodeError extends DerError {}

/** Raised when a schema is invalid or ambiguous, detected at compile time. */
export class SchemaCompileError extends DerError {}
