/**
 * Examiner — the target shape for all detection rules.
 *
 * An Examiner is a TypedRuleV2 with mandatory, declarative metadata that
 * captures the 9-point thoroughness discipline. Each Examiner ships:
 *
 *   1. Research citation          → hypothesis.threat_reference.primary
 *   2. Primary-source uniqueness  → enforced by CI validator across all Examiners
 *   3. Edge-case manifest         → edge_cases.variants (≥5)
 *   4. Adversarial mutations      → edge_cases.adversarial_mutations (≥3)
 *   5. Negative controls          → edge_cases.known_safe_patterns (≥3)
 *   6. CVE replay                 → edge_cases.cve_replays (if CVE-backed)
 *   7. Cross-rule interaction     → edge_cases.interacts_with
 *   8. Calibrated confidence      → TrustedConstant wrapper, enforced by AST scan
 *   9. Red-team corpus replay     → enforced by `pnpm test --filter=red-team`
 *
 * Subclasses implement analyze() using whichever analysis technique they
 * declare in `technique`. The declarative metadata is what the CI validator
 * reads; analyze() is what the red-team fixture runner exercises.
 *
 * Conceptual shift vs v1 rules: an Examiner is not "a pattern." It is a full
 * examination protocol against a specific server. Its finding is the write-up
 * of the examination — dynamic evidence synthesized from what the server
 * actually exposed — not a pre-built template filled in with matched tokens.
 */

import type { TypedRuleV2, RuleResult, RuleRequirements, AnalysisTechnique } from "./base.js";
import { registerTypedRuleV2 } from "./base.js";
import type { AnalysisContext } from "../engine.js";

// ─── Research citation types ────────────────────────────────────────────────

/** A single research anchor: CVE, paper, blog, spec section, MITRE technique, etc. */
export interface ThreatSource {
  /** Source class — determines how the validator verifies uniqueness */
  kind: "CVE" | "paper" | "blog" | "spec" | "mitre" | "framework" | "incident";
  /** Canonical identifier: "CVE-2025-6514", "arXiv:2601.17549", "OWASP-MCP03", "AML.T0054", "RFC-9700" */
  id: string;
  /** URL to the primary source (NVD, arXiv, vendor advisory, spec section) */
  url?: string;
  /** Short human-readable note about what this source demonstrates */
  note?: string;
}

/** A research citation anchoring an Examiner's hypothesis. */
export interface ThreatReference {
  /** The primary source — must be unique across all Examiners (gate #2). */
  primary: ThreatSource;
  /** Supporting sources — do not have to be unique. */
  supporting?: ThreatSource[];
}

/** The hypothesis an Examiner tests against a target server. */
export interface Hypothesis {
  /** One-paragraph statement of the attack being tested */
  statement: string;
  /** Research anchors — primary source is mandatory (gate #1) */
  threat_reference: ThreatReference;
  /** Attack outcome class: "remote-code-execution", "data-exfiltration", ... */
  attack_class: string;
  /** Where this hypothesis came from: "owasp-mcp-top-10", "cve-analysis", "spec-audit" */
  derived_from: string;
}

// ─── Edge-case manifest types ───────────────────────────────────────────────

export type VariantKind = "true-positive" | "true-negative" | "edge-case";

/** An expected-firing fixture variant (gate #3 — ≥5 per Examiner). */
export interface EdgeCaseVariant {
  /** Stable identifier for cross-reference from test output, e.g. "v1-direct-exec-string" */
  id: string;
  kind: VariantKind;
  description: string;
  /** Fixture locator in the red-team corpus. Format: "{fixture-file}:{rule-id}:{fixture-description-substring}" */
  fixture: string;
}

/** Attacker-bypass techniques the rule must handle (gate #4 — ≥3 per Examiner). */
export type BypassTechnique =
  | "unicode-homoglyph"
  | "zero-width-injection"
  | "encoding-base64"
  | "encoding-url"
  | "encoding-hex"
  | "alias-rename"
  | "spread-args"
  | "parameter-alias"
  | "whitespace-injection"
  | "tool-name-shadowing";

export interface AdversarialMutation {
  id: string;
  description: string;
  /** Which bypass technique this mutation exercises */
  bypass: BypassTechnique;
  fixture: string;
}

/** Commonly-confused-but-legitimate patterns (gate #5 — ≥3 per Examiner). */
export interface KnownSafePattern {
  id: string;
  description: string;
  /** Why this pattern is legitimate (shown in audit evidence for ruled-out cases) */
  rationale: string;
  fixture: string;
}

/** CVE replay fixture (gate #6 — required for every CVE-backed Examiner). */
export interface CVEReplay {
  /** The CVE identifier this fixture reproduces */
  cve: string;
  /** Locator in the cve-replays fixture file */
  fixture: string;
  /** Minimum confidence the rule must produce on the replay (typically ≥0.9) */
  expected_confidence_min: number;
}

/** Declared coupling with another rule (gate #7 — prevents silent cross-rule drift). */
export interface RuleInteraction {
  rule_id: string;
  relation: "specialized-by" | "sibling" | "cross-reference" | "related" | "feeds" | "feeds-from";
  note: string;
}

/** The full edge-case manifest for one Examiner. */
export interface EdgeCaseManifest {
  variants: EdgeCaseVariant[];
  adversarial_mutations: AdversarialMutation[];
  known_safe_patterns: KnownSafePattern[];
  cve_replays: CVEReplay[];
  interacts_with: RuleInteraction[];
}

// ─── Calibrated-confidence wrapper (gate #8) ────────────────────────────────

/**
 * Wraps a hardcoded confidence value with a justification string.
 *
 * Gate #8 of the thoroughness discipline: no hardcoded confidence literals in
 * Examiner source unless wrapped in `TrustedConstant(value, reason)`. The
 * validator's AST scan (tools/scripts/validate-examiners.ts) rejects plain
 * numeric literals in property-assignment positions whose name matches
 * /confidence|weight|threshold|score/ when they aren't wrapped here.
 *
 * At runtime this is transparent — it returns the number. At lint time the
 * wrapper call's presence is what satisfies the gate. The reason is captured
 * in the function call itself, so audit reviewers browsing the Examiner's
 * source see *why* a number is hardcoded (e.g. citing CVE analysis, the
 * research paper's headline figure, or an ecosystem-baseline calibration).
 *
 * Use `baselines.zScore(...)` or `EcosystemBaselineStore.lookup(...)` instead
 * of TrustedConstant whenever the number is actually derived from data.
 */
export function TrustedConstant(value: number, reason: string): number {
  if (typeof reason !== "string" || reason.trim().length < 10) {
    throw new Error(
      `TrustedConstant requires a reason string of ≥10 chars explaining the calibration; got: ${JSON.stringify(reason)}`,
    );
  }
  if (!Number.isFinite(value) || value < 0 || value > 1) {
    throw new Error(`TrustedConstant value must be a finite number in [0, 1]; got: ${value}`);
  }
  return value;
}

// ─── Examiner base class ────────────────────────────────────────────────────

/**
 * All detection rules should extend Examiner. It is a thin wrapper over
 * TypedRuleV2 that adds the declarative metadata the 9-point discipline
 * requires. Subclasses still implement analyze() however they want — AST
 * taint, capability graph, entropy, structural parsing — and produce
 * `RuleResult[]` with mandatory evidence chains (inherited from TypedRuleV2).
 */
export abstract class Examiner implements TypedRuleV2 {
  abstract readonly id: string;
  abstract readonly name: string;
  abstract readonly requires: RuleRequirements;
  abstract readonly technique: AnalysisTechnique;

  /** Research-cited hypothesis under test (gate #1). */
  abstract readonly hypothesis: Hypothesis;

  /** Edge-case manifest: variants, adversarial mutations, negative controls, CVE replays, interactions. */
  abstract readonly edge_cases: EdgeCaseManifest;

  /**
   * Run the examination against a target context and return findings.
   *
   * Contract (inherited from TypedRuleV2):
   *  - every RuleResult.chain has ≥1 source + ≥1 sink link
   *  - confidence is derived from the chain via computeConfidence(), not hardcoded
   *  - returning [] is normal — never throw (engine has try/catch, but be clean)
   */
  abstract analyze(context: AnalysisContext): RuleResult[];
}

// ─── Registration ───────────────────────────────────────────────────────────

/**
 * Register an Examiner with the rule engine.
 *
 * This is the preferred entry point for all new rules. It validates the
 * hypothesis shape at load time (fail-fast on authoring mistakes) and then
 * registers via `registerTypedRuleV2`, which also installs a v1-compatible
 * wrapper so the existing engine dispatch path (getTypedRule) works unchanged.
 */
export function registerExaminer(examiner: Examiner): void {
  validateHypothesisShape(examiner);
  validateEdgeCaseShape(examiner);
  registerTypedRuleV2(examiner);
}

function validateHypothesisShape(examiner: Examiner): void {
  const h = examiner.hypothesis;
  if (!h || typeof h.statement !== "string" || h.statement.trim().length < 40) {
    throw new Error(
      `Examiner ${examiner.id}: hypothesis.statement must be ≥40 chars describing the attack class`,
    );
  }
  if (!h.threat_reference?.primary) {
    throw new Error(
      `Examiner ${examiner.id}: hypothesis.threat_reference.primary is mandatory (discipline gate #1 — research citation)`,
    );
  }
  const primary = h.threat_reference.primary;
  if (!primary.kind || !primary.id) {
    throw new Error(
      `Examiner ${examiner.id}: primary threat source must declare {kind, id}; got ${JSON.stringify(primary)}`,
    );
  }
  if (primary.kind === "CVE" && !primary.id.startsWith("CVE-")) {
    throw new Error(
      `Examiner ${examiner.id}: CVE threat source id must start with "CVE-"; got ${primary.id}`,
    );
  }
  if (!h.attack_class || !h.derived_from) {
    throw new Error(
      `Examiner ${examiner.id}: hypothesis must declare attack_class and derived_from`,
    );
  }
}

function validateEdgeCaseShape(examiner: Examiner): void {
  const ec = examiner.edge_cases;
  if (!ec) {
    throw new Error(`Examiner ${examiner.id}: edge_cases manifest is mandatory`);
  }
  // Load-time shape check only — the CI validator enforces the counts (≥5, ≥3, ≥3)
  // across the full fixture corpus. Here we just make sure the arrays exist so
  // the validator has something to walk.
  for (const field of ["variants", "adversarial_mutations", "known_safe_patterns", "cve_replays", "interacts_with"] as const) {
    if (!Array.isArray(ec[field])) {
      throw new Error(`Examiner ${examiner.id}: edge_cases.${field} must be an array`);
    }
  }
}
