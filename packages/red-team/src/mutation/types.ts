/**
 * Mutation-suite types.
 *
 * The mutation auditor applies 8 AST-level mutations to every rule's
 * true-positive fixtures and records which mutations the rule still fires on
 * (`survived`) and which it goes blind to (`blind`). The CHARTER for each rule
 * freezes the survived/blind arrays as an honest false-negative account.
 *
 * This file defines the wire types used throughout the mutation suite:
 *   - `MutationId` — the closed set of 8 mutation names
 *   - `MutationFn` — the pure function shape every mutation implements
 *   - `MutationOutcome` — a single (rule, fixture, mutation) result
 *   - `MutationReport` — the aggregated report written to
 *     `docs/mutations/latest.json`
 */

/**
 * The 8 mutations we run. Names are frozen — CHARTERs reference them directly.
 * If this list changes, every CHARTER that lists `mutations_survived` /
 * `mutations_acknowledged_blind` must be updated in the same commit.
 */
export type MutationId =
  | "rename-danger-symbol"
  | "split-string-literal"
  | "unicode-homoglyph-identifier"
  | "base64-wrap-payload"
  | "intermediate-variable"
  | "add-noop-conditional"
  | "swap-option-shape"
  | "reorder-object-properties";

/** The 8 mutation ids in canonical order. Frozen. */
export const MUTATION_IDS: readonly MutationId[] = [
  "rename-danger-symbol",
  "split-string-literal",
  "unicode-homoglyph-identifier",
  "base64-wrap-payload",
  "intermediate-variable",
  "add-noop-conditional",
  "swap-option-shape",
  "reorder-object-properties",
] as const;

/**
 * Every mutation is a pure function from fixture source text to mutated source
 * text. A mutation that cannot apply (e.g. no object literal with ≥2 properties
 * exists) returns the original text with `notes: "not-applicable"` — it NEVER
 * throws. This is a load-bearing invariant: the runner relies on not-applicable
 * being a distinguishable outcome from an empty / unchanged mutation.
 */
export interface MutationResult {
  mutated: string;
  /** Free-form note — used primarily to signal `not-applicable`. */
  notes?: string;
}

export type MutationFn = (source: string) => MutationResult;

/**
 * One (rule, fixture, mutation) cell of the audit matrix.
 *
 * - `survived`: rule fired ≥1 finding on the mutated variant
 * - `blind`: rule fired 0 findings on the mutated variant, but fired ≥1 on
 *   the un-mutated original (so the absence is mutation-induced, not a broken
 *   fixture). This is the honest false-negative signal.
 * - `not-applicable`: the mutation had no target in this fixture (e.g. no
 *   object literal for `reorder-object-properties`). Excluded from CHARTER lists.
 * - `error`: the mutation or rule threw. Recorded but excluded from CHARTER lists.
 */
export type MutationOutcomeLabel = "survived" | "blind" | "not-applicable" | "error";

export interface MutationOutcome {
  rule_id: string;
  fixture: string;
  mutation: MutationId;
  outcome: MutationOutcomeLabel;
  detail?: string;
  findings_before: number;
  findings_after: number;
}

export interface PerRuleSummary {
  rule_id: string;
  survived: MutationId[];
  acknowledged_blind: MutationId[];
  not_applicable: MutationId[];
  errors: MutationId[];
  /** Fixtures that the rule did NOT fire on even without mutation; excluded from survived/blind lists. */
  fixtures_without_baseline: string[];
  /** Rules with no true-positive fixtures (stub / companion rules). */
  no_fixtures: boolean;
}

export interface MutationReport {
  generated_at: string;
  rules_version: string;
  outcomes: MutationOutcome[];
  per_rule_summary: PerRuleSummary[];
  totals: {
    rules_total: number;
    rules_with_fixtures: number;
    rules_survived_any: number;
    rules_blind_all: number;
    mutation_cells_total: number;
    mutation_cells_survived: number;
    mutation_cells_blind: number;
    mutation_cells_not_applicable: number;
    mutation_cells_errored: number;
  };
}
