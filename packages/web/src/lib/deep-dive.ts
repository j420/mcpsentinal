/**
 * deep-dive.ts — Frozen TypeScript contract for `GET /api/v1/servers/:slug/deep-dive`.
 *
 * This file is consumed by THREE web agents in parallel (Cluster D parts 3, 4, 5):
 *   - Part 3 (this agent): the page restructure + chrome shells
 *   - Part 4: the long-scroll content cards (`<CategorySection/>`,
 *     `<SubCategorySection/>`, `<RuleEvidenceCard/>`)
 *   - Part 5: the sticky rail (`<DeepDiveSidebar/>`)
 *
 * The shape below is identical to what Agent 2 froze on the API side. We
 * cannot import from `@mcp-sentinel/database` (web boundary rule, see
 * Cluster B `framework-labels.ts` precedent) so the contract is mirrored
 * here verbatim.
 *
 * Pure types only. No runtime code. The other two agents `import type`
 * from this file.
 */

// ── Severity ──────────────────────────────────────────────────────────────

/** Standard analyzer severity vocabulary (matches `findings.severity`). */
export type DeepDiveSeverity =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "informational";

/** Per-severity counts. Every level always present, even if zero. */
export interface DeepDiveSeverityBreakdown {
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
}

// ── Coverage band (page-level) ────────────────────────────────────────────

/**
 * Coverage band for the whole deep-dive payload — drives the hero confidence
 * chip. Identical vocabulary to `score_detail.coverage_band` in the slug
 * endpoint so a consumer looking at both endpoints sees one band, not two.
 *
 * `null` is reserved for legacy scans that pre-date the coverage producer.
 */
export type DeepDiveCoverageBand = "high" | "medium" | "low" | "minimal";

// ── Per-rule status ───────────────────────────────────────────────────────

/**
 * Status of a single rule against this server:
 *   - `passed`   — rule executed and produced no findings
 *   - `findings` — rule executed and produced ≥1 finding
 *   - `skipped`  — rule could not execute (input missing, e.g. no source code)
 */
export type DeepDiveRuleStatus = "passed" | "findings" | "skipped";

// ── Rule reference metadata ───────────────────────────────────────────────

/**
 * One framework control reference attached to a rule, e.g.
 * `{ framework: "owasp_mcp", control: "MCP09", label: "Logging & Monitoring" }`.
 */
export interface DeepDiveFrameworkControl {
  framework: string;
  control: string;
  label?: string | null;
}

/**
 * Backing evidence for a rule — produced by `packages/red-team/src/cve-corpus/`
 * and `packages/red-team/src/accuracy/`. Drives the per-finding "Detection
 * Quality" footer (audit invention #4).
 *
 * All fields optional: rules without backing data render an empty footer
 * (the audit doc demands honest gaps over fake numbers).
 */
export interface DeepDiveRuleBacking {
  cve_ids?: string[];
  red_team_fixture_count?: number;
  precision?: number;
  recall?: number;
  last_validated_at?: string | null;
  last_validation_pass?: boolean | null;
}

// ── Single finding (light shape) ──────────────────────────────────────────

/**
 * Compact finding shape rendered inside `<RuleEvidenceCard/>`. The richer
 * Finding type used by `<FindingsEvidenceTab/>` is not re-exported here —
 * the deep-dive endpoint deliberately keeps the contract narrow and the
 * card surfaces the chain via `evidence_chain` directly.
 */
export interface DeepDiveFinding {
  id: string;
  rule_id: string;
  severity: DeepDiveSeverity;
  evidence: string;
  remediation: string;
  /** Phase 1 confidence score (0.0–1.0). Absent on pre-Phase-1 scans. */
  confidence?: number;
  /** Phase 1 structured chain. Absent on pre-Phase-1 scans. */
  evidence_chain?: Record<string, unknown> | null;
  /** Optional cross-walk for inline framework chips on each finding. */
  framework_controls?: DeepDiveFrameworkControl[];
}

// ── Per-rule node ─────────────────────────────────────────────────────────

/**
 * One rule's worth of deep-dive data — the leaf that `<RuleEvidenceCard/>`
 * renders. Always carries the rule's identity, mappings, methodology and
 * status; carries findings only when `status === "findings"`.
 */
export interface DeepDiveRule {
  rule_id: string;
  name: string;
  severity: DeepDiveSeverity;
  /** Engine category (e.g. `code-analysis`, `protocol-surface`). */
  category: string;
  /** OWASP MCP control id, if mapped (e.g. `MCP09`). */
  owasp: string | null;
  /** MITRE ATLAS technique id, if mapped (e.g. `AML.T0054`). */
  mitre: string | null;
  /** One-paragraph human-readable summary. */
  summary: string;
  /** Cross-framework control references for the rule. */
  framework_controls: DeepDiveFrameworkControl[];
  /** Detection technique blurb (e.g. "AST taint", "entropy + Levenshtein"). */
  methodology: string;
  /** Red-team / CVE backing — drives the per-finding quality footer. */
  backing: DeepDiveRuleBacking;
  /** Remediation copy for the rule when status is `findings`. */
  remediation: string;
  /** Whether the rule passed, fired, or was skipped on this scan. */
  status: DeepDiveRuleStatus;
  /** Findings produced by this rule (empty when status !== "findings"). */
  findings: DeepDiveFinding[];
  /** Anchor ids of other categories/sub-categories this rule appears under. */
  cross_referenced_in?: string[];
}

// ── Counts at category / sub-category level ───────────────────────────────

/**
 * Aggregate counts attached to every category and sub-category. Every field
 * is required and integer-valued so consumers never have to guard against
 * undefined arithmetic.
 */
export interface DeepDiveCounts {
  rules_total: number;
  rules_passed: number;
  rules_with_findings: number;
  rules_skipped: number;
  finding_count: number;
  severity_breakdown: DeepDiveSeverityBreakdown;
}

// ── Sub-category node ─────────────────────────────────────────────────────

/**
 * One sub-category — a thematic grouping of rules under a parent category.
 * Renders as a `<SubCategorySection/>` inside the long-scroll main column.
 */
export interface DeepDiveSubCategory {
  /** Stable anchor id (used by both the sidebar and `id="…"` deep links). */
  id: string;
  title: string;
  summary: string;
  counts: DeepDiveCounts;
  rules: DeepDiveRule[];
}

// ── Category node ─────────────────────────────────────────────────────────

/**
 * One top-level category. Renders as a `<CategorySection/>` heading plus
 * all sub-categories beneath it.
 */
export interface DeepDiveCategory {
  /** Stable anchor id. */
  id: string;
  title: string;
  summary: string;
  /** Frameworks this category contributes evidence toward (label form). */
  frameworks: string[];
  counts: DeepDiveCounts;
  sub_categories: DeepDiveSubCategory[];
}

// ── Coverage / hero summary ───────────────────────────────────────────────

/**
 * Page-level coverage summary — drives the deep-dive hero chrome (score
 * confidence chip + the `source / live / deps` pips below the score).
 *
 * `coverage_band: null` means the producer ran but had no signal; treat as
 * "minimal" UI-side or hide the chip. The page never crashes on null.
 */
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

/**
 * Minimal identity stub returned alongside the deep-dive payload. The hero
 * chrome already has the full server record from the slug endpoint; this
 * stub only confirms the slug+name agree (defence-in-depth against routing
 * mistakes).
 */
export interface DeepDiveServerStub {
  slug: string;
  name: string;
}

// ── Full envelope ─────────────────────────────────────────────────────────

/**
 * The full envelope returned by `GET /api/v1/servers/:slug/deep-dive`.
 *
 * Shape:
 * ```
 * {
 *   data: {
 *     server:     DeepDiveServerStub,
 *     coverage:   DeepDiveCoverageSummary,
 *     categories: DeepDiveCategory[],
 *   }
 * }
 * ```
 */
export interface DeepDiveData {
  server: DeepDiveServerStub;
  coverage: DeepDiveCoverageSummary;
  categories: DeepDiveCategory[];
}

export interface DeepDiveResponse {
  data: DeepDiveData;
}
