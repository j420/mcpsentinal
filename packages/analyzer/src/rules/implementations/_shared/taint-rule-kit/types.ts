/**
 * Shared taint-rule-kit — structured types for taint-based v2 rules.
 *
 * Six rules (C4, C12, C13, C16, K9, J2) share a common detection pipeline:
 *   1. Run AST taint analysis (analyzeASTTaint).
 *   2. Fall back to lightweight regex-based taint (analyzeTaint) if AST found
 *      nothing — the lightweight analyser lives in `analyzers/taint.ts` whose
 *      regex literals are exempt from the implementations-directory guard.
 *   3. Filter flows by sink category (per rule).
 *   4. Convert each flow into structured TaintRuleFacts (Location-kinded).
 *
 * `index.ts` of each rule consumes TaintRuleFacts and emits a v2 RuleResult
 * with its own CHARTER-mandated factors, severity, remediation, and threat
 * reference. The shared kit never produces a RuleResult directly — every
 * per-rule judgement happens in the rule's own code.
 *
 * No regex literals anywhere in this directory. No string-literal arrays > 5.
 * All configuration (which sink categories a rule cares about, which
 * confidence cap to apply, …) is passed through typed config objects from
 * the rule's index.ts — the data itself lives in `data/*.json`.
 */

import type { Location } from "../../../location.js";

// ─── Fact types emitted by the kit to rule index.ts ───────────────────────

/** One hop on the source→sink taint path. */
export interface TaintPathStep {
  /** Narrow step kind — useful for verification-step rendering. */
  kind: "assignment" | "destructure" | "template-embed" | "function-call" | "direct-pass";
  /** Short human label ("req.body.cmd → cmd"). */
  expression: string;
  /** Where the step occurs. Always kind:"source". */
  location: Location;
}

/** What the kit knows about a sanitiser on the path (if any). */
export interface SanitiserFact {
  /** Canonical name / expression text of the sanitiser. */
  name: string;
  /** Where it appears. */
  location: Location;
  /**
   * Whether the sanitiser identity is on the rule's charter-audited list.
   * False means "a sanitiser was observed, but we can't confirm it does
   * anything real" (CHARTER lethal edge case across all six rules).
   */
  charterKnown: boolean;
}

/** One AST-confirmed or lightweight-confirmed source→sink flow. */
export interface TaintFact {
  /** Which analyser produced the fact. */
  analyser: "ast" | "lightweight";

  /** Untrusted source. */
  sourceLocation: Location;
  /** Short label ("req.body.cmd"). */
  sourceExpression: string;
  /** Category string reported by the analyser ("http_body", "environment", …). */
  sourceCategory: string;

  /** Intermediate propagation hops. Length 0 means direct source→sink. */
  path: TaintPathStep[];

  /** Dangerous call / operation. */
  sinkLocation: Location;
  /** Short label ("exec(cmd)"). */
  sinkExpression: string;
  /** Sink category from the analyser. */
  sinkCategory: string;

  /** Sanitiser fact (null if none was observed). */
  sanitiser: SanitiserFact | null;

  /** Raw analyser confidence before index.ts applies rule-specific adjustments. */
  rawConfidence: number;
}

/** Rule-agnostic gather result. */
export interface TaintGatherResult {
  /** High-level mode for index.ts to branch on. */
  mode: "absent" | "test-file" | "facts";
  /** Filename the kit attributes every Location to. */
  file: string;
  /** Facts — empty when mode !== "facts". */
  facts: TaintFact[];
}

// ─── Config passed by each rule's index.ts ────────────────────────────────

/**
 * Rule-level config that drives the shared gather() function. Data is
 * passed in rather than statically imported so each rule owns its own
 * filtering / sanitiser list.
 */
export interface TaintRuleConfig {
  /** Rule id ("C4", "C12", …) — used for Location.file fallback name. */
  ruleId: string;
  /**
   * Sink categories reported by `analyzeASTTaint`. Any flow whose
   * `sink.category` is NOT in this set is discarded by the kit.
   */
  astSinkCategories: readonly string[];
  /**
   * Sink categories reported by `analyzeTaint` (the lightweight analyser).
   * These use a different taxonomy than the AST analyser.
   */
  lightweightSinkCategories: readonly string[];
  /**
   * Sanitiser names (function / method identifiers) that the charter
   * considers audited-safe. The kit compares observed sanitiser names to
   * this set and records the result on SanitiserFact.charterKnown.
   */
  charterSanitisers: ReadonlySet<string>;
}
