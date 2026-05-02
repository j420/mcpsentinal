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

// ── Story-lens augmentations (Phase 2 of the redesign) ─────────────────────
// Every field below is optional on the response — present when the backend
// has the data, absent otherwise. Components MUST treat absence as "no data
// on file" (honest gap, render an empty state) rather than guessing.
//
// The shapes mirror packages/api/src/deep-dive.ts verbatim. Web cannot
// import from the api package directly (boundary rule, see CLAUDE.md), so
// the types are duplicated here as the single web-side source of truth.

/** One synthesized multi-step kill chain involving this server. Mirrors
 *  `DeepDiveAttackChain` in `packages/api/src/deep-dive.ts`. Populated from
 *  `DatabaseQueries.getAttackChainsForServer()`. */
export interface DeepDiveAttackChain {
  chain_id: string;
  /** KC01–KC07 stable id. */
  kill_chain_id: string;
  kill_chain_name: string;
  /** Ordered attack steps. Shape stable: each entry is
   *  `{ ordinal, server_id, server_name, role, capabilities_used,
   *  tools_involved, edge_to_next?, narrative }`. We accept `unknown[]`
   *  here so the contract here doesn't drift if the engine adds fields. */
  steps: unknown[];
  /** [0..1]. */
  exploitability_overall: number;
  /** "critical" | "high" | "medium" | "low". */
  exploitability_rating: string;
  narrative: string;
  /** Pre-computed mitigations — each entry shape:
   *  `{ action, target_server_name?, description, breaks_steps: number[],
   *  effect }`. Pass-through. */
  mitigations: unknown[];
  owasp_refs: string[];
  mitre_refs: string[];
}

/** A cross-server risk edge involving this server. Mirrors
 *  `DeepDiveRiskEdge` in the api package. */
export interface DeepDiveRiskEdge {
  config_id: string;
  from_server: { id: string; name: string; slug: string };
  to_server: { id: string; name: string; slug: string };
  /** "data_flow" | "credential_chain" | "injection_path" |
   *  "config_poisoning" | "memory_pollution" | "privilege_escalation" |
   *  "exfiltration_chain". Stable wire string. */
  edge_type: string;
  /** P01–P12 stable id. */
  pattern_id: string;
  /** "critical" | "high" | "medium" | "low". */
  severity: string;
  description: string;
  owasp_category: string | null;
  mitre_technique: string | null;
}

/** Risk-matrix capability classification of this server's tools.
 *  Mirrors `CapabilityNode` from `@mcp-sentinel/risk-matrix`. */
export interface DeepDiveCapabilityNode {
  server_id: string;
  server_name: string;
  server_slug: string;
  latest_score: number | null;
  /** Capability tags from the 14-element vocabulary in risk-matrix. */
  capabilities: string[];
  is_injection_gateway: boolean;
  is_shared_writer: boolean;
  category: string | null;
}

/** Provenance triple stamped on every deep-dive response. */
export interface DeepDiveProvenance {
  /** Last completed scan id whose findings populate this view. */
  scan_id: string | null;
  /** ISO 8601 of `scans.completed_at`. */
  scan_completed_at: string | null;
  /** rules-package version the scan ran against. */
  rules_version: string | null;
  /** Sentinel build version. */
  sentinel_version: string;
  /** Public HMAC key id for verifying per-finding signed receipts. The
   *  raw secret is NEVER on the wire. */
  signing_key_id: string;
}

/** One Phase-4 CVE corpus replay validating a rule. Mirrors
 *  `CveReplayValidation` from `@mcp-sentinel/red-team`. */
export interface DeepDiveCveValidation {
  /** "CVE-YYYY-NNNN" or "research-kebab-id". */
  id: string;
  /** "cve" | "research". */
  kind: string;
  title: string;
  source_url: string;
  /** ISO 8601 (YYYY-MM-DD). */
  disclosed: string;
  cvss_v3: number | null;
  /** "critical" | "high" | "medium" | "low" | "informational". */
  min_severity: string;
}

/* ── Module-augmentation: attach optional augmentations to existing
 *    DeepDiveData and DeepDiveRule shapes. We extend the interfaces in
 *    place rather than declaring new ones because the backend layers the
 *    fields on the SAME object via passthrough — same JSON, same TS
 *    shape. Components only access these fields after a presence check. */

declare module "./deep-dive" {
  interface DeepDiveData {
    /** Kill chains synthesized by `packages/attack-graph` for this server.
     *  Absent / empty when no chains involve this server. */
    attack_chains?: DeepDiveAttackChain[];
    /** Cross-server P-pattern edges. Absent / empty when this server has
     *  not participated in a risk-matrix run. */
    risk_edges?: DeepDiveRiskEdge[];
    /** Risk-matrix capability surface for this server. */
    capability_node?: DeepDiveCapabilityNode;
    /** Provenance triple — every claim on the page traces back to this. */
    provenance?: DeepDiveProvenance;
  }

  interface DeepDiveRule {
    /** Phase-4 CVE replay corpus coverage for this rule. Absent when the
     *  rule has no replay coverage on file. */
    validated_by_cve?: DeepDiveCveValidation[];
  }
}
