/**
 * Runtime schema model. Schemas are plain data; `compileSchema` (compile.ts)
 * turns them into an executable plan with tag dispatch tables precomputed.
 */

export type TagClassName = 'universal' | 'application' | 'context' | 'private';

/** Explicit tag written next to a type, e.g. `[2]` or `[APPLICATION 3]`. */
export interface Tag {
  number: number;
  class?: TagClassName; // defaults to 'context'
}

export type SchemaNode =
  | PrimitiveNode
  | SequenceNode
  | SetNode
  | SequenceOfNode
  | ChoiceNode
  | RefNode;

export interface PrimitiveNode {
  kind: 'boolean' | 'integer' | 'octetString' | 'bitString' | 'null' | 'oid' | 'utf8String' | 'enum';
  tag?: Tag; // presence => explicit wrapping; with `implicit: true` => implicit retag
  implicit?: boolean;
}

export interface SequenceNode {
  kind: 'sequence';
  fields: Field[];
  tag?: Tag;
  implicit?: boolean;
}

export interface SetNode {
  kind: 'set';
  fields: Field[];
  tag?: Tag;
  implicit?: boolean;
}

export interface SequenceOfNode {
  kind: 'sequenceOf';
  element: SchemaNode;
  tag?: Tag;
  implicit?: boolean;
}

export interface ChoiceNode {
  kind: 'choice';
  alternatives: SchemaNode[];
  tag?: Tag; // explicit only: CHOICE has no universal tag of its own
  /** Rejected at compile time: CHOICE cannot be implicitly tagged. */
  implicit?: boolean;
}

/** Named reference into the `named` map passed to compileSchema; enables recursion. */
export interface RefNode {
  kind: 'ref';
  name: string;
  tag?: Tag;
  implicit?: boolean;
}

export interface Field {
  name: string;
  type: SchemaNode;
  optional?: boolean;
  /** DEFAULT value (JSON form: number/string/boolean/null). */
  default?: unknown;
}

/** Recursive walk over a schema tree, following named refs cycle-safely. */
export const walkSchema = (
  node: SchemaNode,
  named: Record<string, SchemaNode>,
  visit: (node: SchemaNode) => void,
): void => {
  const seenObjects = new Set<SchemaNode>();
  const seenRefs = new Set<string>();
  const walk = (n: SchemaNode): void => {
    if (seenObjects.has(n)) return;
    seenObjects.add(n);
    visit(n);
    switch (n.kind) {
      case 'sequence':
      case 'set':
        for (const f of n.fields) walk(f.type);
        break;
      case 'sequenceOf':
        walk(n.element);
        break;
      case 'choice':
        for (const a of n.alternatives) walk(a);
        break;
      case 'ref':
        if (!seenRefs.has(n.name)) {
          seenRefs.add(n.name);
          const target = named[n.name];
          if (target) walk(target);
        }
        break;
    }
  };
  walk(node);
};
