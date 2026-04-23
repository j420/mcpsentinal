import type { Severity } from "@mcp-sentinel/database";

/**
 * Public framework identifier used on the wire, in signed reports, in URL
 * paths, and in badge files. Bump {@link ComplianceReport.version} on any
 * change to this union.
 */
export type FrameworkId =
  | "eu_ai_act"
  | "iso_27001"
  | "owasp_mcp"
  | "owasp_asi"
  | "cosai_mcp"
  | "maestro"
  | "mitre_atlas";

export const FRAMEWORK_IDS: readonly FrameworkId[] = [
  "eu_ai_act",
  "iso_27001",
  "owasp_mcp",
  "owasp_asi",
  "cosai_mcp",
  "maestro",
  "mitre_atlas",
];

/**
 * Per-control assessment outcome.
 * - `met`: at least one assessor rule exists and none fired
 * - `unmet`: at least one assessor rule fired at or above the control's unmet_threshold
 * - `partial`: assessor rules fired but all below the unmet_threshold
 * - `not_applicable`: no assessor rule exists OR the control has been deemed out-of-scope
 */
export type ControlStatus = "met" | "unmet" | "partial" | "not_applicable";

export type ConfidenceBand = "high" | "medium" | "low" | "minimal";

/**
 * One piece of finding-backed evidence cited against a single control. Each
 * entry must correspond to a real persisted finding row — reports must not
 * fabricate evidence. The `evidence_summary` is the first 200 chars of the
 * finding.evidence string; regulators can look up the full row by finding_id.
 */
export interface ControlEvidence {
  finding_id: string;
  rule_id: string;
  severity: Severity;
  evidence_summary: string;
  confidence: number;
}

/**
 * A single control's assessment within a framework. Control ids are stable
 * across framework versions (e.g. "Art.14", "A.5.15", "MCP03", "AML.T0054")
 * so reports are comparable over time.
 */
export interface ControlResult {
  control_id: string;
  control_name: string;
  control_description: string;
  source_url: string;
  status: ControlStatus;
  evidence: ControlEvidence[];
  /** Human-language explanation of WHY the status is what it is, mechanically generated from the evidence. */
  rationale: string;
  /** Steps that would change status from unmet/partial to met. Deduplicated, capped at 5 per control. */
  required_mitigations: string[];
  /** Rule ids that ASSESS this control regardless of whether they fired. Used for transparent coverage reporting. */
  assessor_rule_ids: string[];
}

/**
 * Placeholder shape Phase 5.3 (kill-chain integration) will populate. Kept
 * in this package so renderers can depend on a stable structure without
 * pulling in `@mcp-sentinel/attack-graph` at compile time.
 */
export interface KillChainNarrative {
  /** "KC01" .. "KC07" */
  kc_id: string;
  name: string;
  /** Exploitability score from packages/attack-graph (0.0-1.0 composite). */
  severity_score: number;
  /** Multi-paragraph human-readable text; renderers emit verbatim. */
  narrative: string;
  contributing_rule_ids: string[];
  /** Ids from the Phase 4 CVE replay corpus that demonstrate this kill-chain pattern. */
  cve_evidence_ids: string[];
  mitigations: string[];
}

/**
 * Aggregate overall-status derived from the per-control summary. Distinct
 * from the four control statuses because regulators ask "is this server
 * compliant with <framework>?" as a single-word answer.
 */
export type OverallStatus =
  | "compliant"
  | "non_compliant"
  | "partially_compliant"
  | "insufficient_evidence";

export interface ReportSummary {
  total_controls: number;
  met: number;
  unmet: number;
  partial: number;
  not_applicable: number;
  overall_status: OverallStatus;
}

export interface ReportServer {
  slug: string;
  name: string;
  github_url: string | null;
  /** scan row id this report is built from (uuid). */
  scan_id: string;
}

export interface ReportFramework {
  id: FrameworkId;
  name: string;
  version: string;
  /** ISO date (YYYY-MM-DD). */
  last_updated: string;
  /** Canonical URL for the framework's control text. */
  source_url: string;
}

export interface ReportAssessment {
  /** ISO 8601 timestamp. */
  assessed_at: string;
  rules_version: string;
  sentinel_version: string;
  coverage_band: ConfidenceBand;
  coverage_ratio: number;
  techniques_run: string[];
}

/**
 * Unsigned report body. Canonicalised + HMAC-signed to produce
 * {@link SignedComplianceReport}. NEVER mutate after signing — the
 * signature covers these bytes.
 */
export interface ComplianceReport {
  version: "1.0";
  server: ReportServer;
  framework: ReportFramework;
  assessment: ReportAssessment;
  controls: ControlResult[];
  summary: ReportSummary;
  kill_chains: KillChainNarrative[];
  /** 3-5 sentence plain-English executive summary for regulators. */
  executive_summary: string;
}

/**
 * HMAC attestation envelope. The `report` field is the exact canonicalized
 * body whose bytes were signed; the outer `attestation` object is NOT part
 * of the signed payload. Verifiers re-canonicalize `signed.report` and
 * recompute the HMAC.
 */
export interface SignedComplianceReport {
  report: ComplianceReport;
  attestation: {
    algorithm: "HMAC-SHA256";
    /** Base64 (standard, not URL-safe) of the HMAC-SHA256 tag. */
    signature: string;
    /** Public identifier of the signing key. Does NOT reveal the secret. */
    key_id: string;
    /** ISO 8601 timestamp set at sign time. */
    signed_at: string;
    /** Stable issuer string embedded in the signature line; regulators use this to identify the signer. */
    signer: string;
    canonicalization: "RFC8785";
  };
}

/**
 * Minimal input finding shape accepted by {@link buildReport}. Mirrors the
 * persistence shape in `@mcp-sentinel/database` but narrowed to the fields
 * the report builder actually reads — keeps this package loosely coupled
 * from the full Finding schema.
 */
export interface ReportInputFinding {
  id: string;
  rule_id: string;
  severity: Severity;
  evidence: string;
  confidence: number;
  remediation: string;
}
