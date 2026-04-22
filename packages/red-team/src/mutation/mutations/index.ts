/**
 * Mutation catalogue. Ordered to match the canonical MUTATION_IDS array in
 * `../types.ts`. The runner iterates this catalogue for every (rule, fixture)
 * pair; the CHARTER-parity guard asserts that the catalogue size matches
 * MUTATION_IDS.length to prevent accidental drift.
 */

import type { MutationFn, MutationId } from "../types.js";

import { renameDangerSymbol } from "./rename-danger-symbol.js";
import { splitStringLiteral } from "./split-string-literal.js";
import { unicodeHomoglyphIdentifier } from "./unicode-homoglyph-identifier.js";
import { base64WrapPayload } from "./base64-wrap-payload.js";
import { intermediateVariable } from "./intermediate-variable.js";
import { addNoopConditional } from "./add-noop-conditional.js";
import { swapOptionShape } from "./swap-option-shape.js";
import { reorderObjectProperties } from "./reorder-object-properties.js";

export interface MutationEntry {
  id: MutationId;
  apply: MutationFn;
  /** One-line description for logs / reports. */
  description: string;
}

export const MUTATION_CATALOGUE: ReadonlyArray<MutationEntry> = [
  {
    id: "rename-danger-symbol",
    apply: renameDangerSymbol,
    description: "Rewire a sensitive-sink call through an alias const to test symbol-binding resolution.",
  },
  {
    id: "split-string-literal",
    apply: splitStringLiteral,
    description: "Split a string literal > 4 chars with `+` concatenation to test linguistic signal reassembly.",
  },
  {
    id: "unicode-homoglyph-identifier",
    apply: unicodeHomoglyphIdentifier,
    description: "Replace one Latin char inside a string literal with a Cyrillic/Greek homoglyph.",
  },
  {
    id: "base64-wrap-payload",
    apply: base64WrapPayload,
    description: "Wrap a string literal in Buffer.from(<b64>, 'base64').toString() to test encoding blind-spots.",
  },
  {
    id: "intermediate-variable",
    apply: intermediateVariable,
    description: "Insert two pass-through const bindings between taint source and sink.",
  },
  {
    id: "add-noop-conditional",
    apply: addNoopConditional,
    description: "Wrap a sink statement in `if (true) { ... }` to test nested-statement traversal.",
  },
  {
    id: "swap-option-shape",
    apply: swapOptionShape,
    description: "Swap `shell: true` for `shell: \"bash\"` (same behaviour, different AST shape).",
  },
  {
    id: "reorder-object-properties",
    apply: reorderObjectProperties,
    description: "Reverse the property order of an object literal with ≥ 2 properties.",
  },
] as const;
