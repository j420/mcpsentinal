/**
 * deep-dive.ts — Frozen TypeScript contract for `GET /api/v1/servers/:slug/deep-dive`.
 *
 * Mirrors `packages/database/src/schemas.ts` DeepDive*Schema exactly.
 * Web cannot import from `@mcp-sentinel/database` (web/CLAUDE.md boundary
 * rule); the contract is duplicated here verbatim. Cluster D reviewer B5
 * caught the prior version inventing field names — this file is now the
 * single source of truth on the web side, and field names match the DB
 * schema 1:1.
 *
 * Zero runtime code. Components import types only.
 *
 * History note (Cluster D reviewer punch-list B5):
 *   - `framework`/`control`/`label?` → `framework_id`/`control_id`/`control_title`
 *   - `cve_ids`/`red_team_fixture_count` → `cve_replay_ids`/`fixture_count`
 *   - `methodology: string` → `methodology: DeepDiveMethodology` (object)
 *   - `cross_referenced_in: string[]` → `Array<{category_id, sub_category_id}>`
 *   - `DeepDiveFinding.rule_id` removed (API does not ship it; the parent
 *     rule already carries the rule_id)
 *   - `DeepDiveRuleBacking` deleted in favour of `DetectionQuality` (single
 *     web-side type for both `<DetectionQualityFooter/>` Cluster C consumer
 *     and the new Deep Dive consumer — Cluster B B1 multi-endpoint lesson).
 */

// ── Severity ──────────────────────────────────────────────────────────────

export type DeepDiveSeverity =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "informational";

export interface DeepDiveSeverityBreakdown {
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
}

// ── Coverage band (page-level) ────────────────────────────────────────────

export type DeepDiveCoverageBand = "high" | "medium" | "low" | "minimal";

// ── Per-rule status ───────────────────────────────────────────────────────

export type DeepDiveRuleStatus = "passed" | "findings" | "skipped";

// ── Framework cross-walk reference ─────────────────────────────────────────

/**
 * One framework control reference. Mirrors `FrameworkControlMappingSchema`
 * in the DB schema verbatim. Identical shape to what `<FindingsEvidenceTab/>`
 * (Cluster B) consumes from `/findings` and `/servers/:slug` — single
 * web-side type for both the Deep Dive page and the Findings tab.
 */
export interface DeepDiveFrameworkControl {
  framework_id: string;
  control_id: string;
  control_title: string;
}

// ── Detection quality (rule backing) ──────────────────────────────────────

/**
 * Validation backing for a rule — produced by `packages/red-team/src/cve-corpus/`
 * and `packages/red-team/src/accuracy/`. Mirrors `DetectionQualitySchema`
 * in the DB schema verbatim. The same shape Cluster C's
 * `<DetectionQualityFooter/>` consumes; the Deep Dive page reuses it
 * unchanged.
 *
 * Two distinct empty states (handled by consumers):
 *   - whole field is `null` → rule not yet wired into either harness
 *   - non-null but precision/recall null AND fixture_count=0 AND
 *     cve_replay_ids=[] → harness wired but no validation runs yet
 */
export interface DetectionQuality {
  precision: number | null;
  recall: number | null;
  fixture_count: number;
  cve_replay_ids: string[];
  last_validated_at: string | null;
}

// ── Methodology (per-rule) ─────────────────────────────────────────────────

/**
 * Mirrors `DeepDiveMethodologySchema`. Drives the "TEST METHODOLOGY"
 * block on each `<RuleEvidenceCard/>`.
 *
 * `verified_edge_cases` is the public name for the CHARTER's
 * `lethal_edge_cases` — renamed at the API projection layer because
 * "verified" reads better in regulator-facing UI than "lethal".
 */
export interface DeepDiveMethodology {
  technique: string;
  verified_edge_cases: string[];
  edge_case_strategies: string[];
  confidence_cap: number | null;
}

// ── Single finding (rule-grouped) ──────────────────────────────────────────

/**
 * One per-finding row inside a rule. Mirrors `DeepDiveFindingSchema` in
 * the DB schema. Deliberately a SUBSET of the public Finding shape:
 *   - no rule_id (the parent rule already carries it)
 *   - no framework_controls / detection_quality (those live on the parent
 *     rule, not duplicated per finding — single source of truth per rule)
 */
export interface DeepDiveFinding {
  id: string;
  severity: DeepDiveSeverity;
  confidence: number;
  evidence: string;
  /** Existing EvidenceChain from packages/analyzer/src/evidence.ts. */
  evidence_chain: Record<string, unknown> | null;
  remediation: string;
}

// ── Cross-reference back-pointer ───────────────────────────────────────────

/**
 * Pointer back to a (category, sub-category) where this rule ALSO appears
 * as a secondary placement. The taxonomy assigns each rule to exactly ONE
 * canonical sub-category; cross-references render as a "see canonical"
 * link from the secondary sites. Empty/absent in the common case.
 */
export interface DeepDiveCrossReference {
  category_id: string;
  sub_category_id: string;
}

// ── Per-rule node ─────────────────────────────────────────────────────────

/**
 * One rule's worth of deep-dive data. Mirrors `DeepDiveRuleSchema`
 * verbatim. The leaf that `<RuleEvidenceCard/>` renders.
 */
export interface DeepDiveRule {
  rule_id: string;
  name: string;
  severity: DeepDiveSeverity;
  /** Legacy letter-category (e.g. "C", "K") — useful for filters. */
  category: string;
  owasp: string | null;
  mitre: string | null;
  summary: string;
  framework_controls: DeepDiveFrameworkControl[];
  methodology: DeepDiveMethodology;
  /** Detection-quality backing — `null` when the rule is not yet wired. */
  backing: DetectionQuality | null;
  remediation: string;
  status: DeepDiveRuleStatus;
  /** Findings for this rule against this server. Empty when status !== "findings". */
  findings: DeepDiveFinding[];
  /** Secondary placements (taxonomy cross-references). Optional. */
  cross_referenced_in?: DeepDiveCrossReference[];
}

// ── Counts at category / sub-category level ───────────────────────────────

export interface DeepDiveCounts {
  rules_total: number;
  rules_passed: number;
  rules_with_findings: number;
  rules_skipped: number;
  finding_count: number;
  severity_breakdown: DeepDiveSeverityBreakdown;
}

// ── Sub-category node ─────────────────────────────────────────────────────

export interface DeepDiveSubCategory {
  id: string;
  title: string;
  summary: string;
  counts: DeepDiveCounts;
  rules: DeepDiveRule[];
}

// ── Category node ─────────────────────────────────────────────────────────

export interface DeepDiveCategory {
  id: string;
  title: string;
  summary: string;
  /** Verbatim from taxonomy YAML — e.g. ["MCP01", "ASI01"]. */
  frameworks: string[];
  counts: DeepDiveCounts;
  sub_categories: DeepDiveSubCategory[];
}

// ── Coverage / hero summary ───────────────────────────────────────────────

export interface DeepDiveCoverageSummary {
  coverage_band: DeepDiveCoverageBand | null;
  total_rules: number;
  rules_executed: number;
  rules_skipped_no_data: number;
  rules_with_findings: number;
  total_findings: number;
  severity_breakdown: DeepDiveSeverityBreakdown;
}

// ── Server identity (light) ───────────────────────────────────────────────

export interface DeepDiveServerStub {
  slug: string;
  name: string;
}

// ── Full envelope ─────────────────────────────────────────────────────────

export interface DeepDiveData {
  server: DeepDiveServerStub;
  coverage: DeepDiveCoverageSummary;
  categories: DeepDiveCategory[];
}

export interface DeepDiveResponse {
  data: DeepDiveData;
}

// ── Backwards-compat alias (deprecated) ───────────────────────────────────

/**
 * Old name for `DetectionQuality`. Kept as a type alias so any in-flight
 * imports do not break during the Cluster D B5 rewrite. New code should
 * import `DetectionQuality` directly.
 *
 * @deprecated Use `DetectionQuality` instead.
 */
export type DeepDiveRuleBacking = DetectionQuality;
