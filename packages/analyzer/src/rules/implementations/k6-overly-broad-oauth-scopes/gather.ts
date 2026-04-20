/**
 * K6 evidence gathering — deterministic, AST-only.
 *
 * Surface: source-code assignments of OAuth scope values. Each finding
 * points to one assignment — a property assignment (`scope: "admin"` in
 * an object literal), a binary assignment (`oauthConfig.scope = "*"`),
 * or a variable initialiser where the declared name matches an OAuth
 * scope vocabulary.
 *
 * The classifier splits detection into two layers:
 *
 *   1. HOW is the scope WRITTEN? — structural AST pattern matching of
 *      the assignment target against `OAUTH_SCOPE_PROPERTY_NAMES` (or
 *      `AMBIGUOUS_SCOPE_PROPERTY_NAMES` when the enclosing object
 *      exposes corroborating OAuth keys).
 *
 *   2. WHAT is the scope VALUE? — classification of each scope token
 *      against the broad-scope vocabulary: exact match on wildcard,
 *      exact match on admin, exact match on broad-prefixed, or
 *      structural suffix check on colon/dot-delimited scope IDs.
 *
 * Zero regex. No string-literal arrays > 5. All vocabulary lives under
 * `./data/*.ts` as Record<string, X> object literals.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import type { ScopeSeverity } from "./data/broad-scopes.js";
import { gatherFile } from "./gather-ast.js";

// ─── Public types ──────────────────────────────────────────────────────────

export interface ScopeMatch {
  scope: string;
  severity: ScopeSeverity;
  /** Why this scope was classified as broad/admin/wildcard — the rule the classifier applied. */
  rationale: string;
}

export interface ScopeAssignment {
  /** The property name or assignment-target tail ("scope", "scopes", etc.). */
  propertyName: string;
  /** Whether this was matched via the ambiguous-name + OAuth-context path. */
  matchedViaOAuthContext: boolean;
  /** The raw source text of the scope value expression (trimmed, length-capped). */
  valueText: string;
  /** The full line text at the assignment location (trimmed, length-capped). */
  lineText: string;
  /** Location of the assignment. */
  location: Location; // kind: "source"
  /** Structured Location for the scope-carrying value. */
  valueLocation: Location; // kind: "source"
  /** Broad-scope matches found inside the value. */
  broadScopes: ScopeMatch[];
  /** Worst severity across all matches. */
  worstSeverity: ScopeSeverity | null;
  /** True when the value expression resolves to user-input data. */
  userControlled: boolean;
  /** Identifier chain that led to the user-input conclusion. */
  userInputChain: string[];
  /** Value-shape class for narrative + factor differentiation. */
  valueShape: "string" | "array" | "template" | "identifier" | "property-access" | "other";
}

export interface FileEvidence {
  file: string;
  assignments: ScopeAssignment[];
  isTestFile: boolean;
}

export interface K6Gathered {
  perFile: FileEvidence[];
}

// ─── Entry point ───────────────────────────────────────────────────────────

export function gatherK6(context: AnalysisContext): K6Gathered {
  const perFile: FileEvidence[] = [];
  const files = collectSourceFiles(context);
  for (const [file, text] of files) {
    perFile.push(gatherFile(file, text));
  }
  return { perFile };
}

function collectSourceFiles(context: AnalysisContext): Map<string, string> {
  const out = new Map<string, string>();
  if (context.source_files && context.source_files.size > 0) {
    for (const [k, v] of context.source_files) out.set(k, v);
    return out;
  }
  if (context.source_code) {
    out.set("<concatenated-source>", context.source_code);
  }
  return out;
}
