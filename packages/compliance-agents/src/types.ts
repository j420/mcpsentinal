/**
 * Adversarial Compliance Framework — Core Types
 *
 * The hierarchy:
 *   FrameworkAgent
 *     └── Category
 *          └── ComplianceRule
 *               └── ComplianceTest[]   ← synthesized at runtime
 *                    └── ComplianceFinding
 *
 * The "evidence bundle" is the deterministic substrate the LLM reasons over.
 * The LLM never reads raw server source; it only reads bundles produced by
 * the rule's `gatherEvidence()` step.
 */

import type { EvidenceChain } from "@mcp-sentinel/analyzer";
import type { Severity } from "@mcp-sentinel/database";

// ─── Frameworks ─────────────────────────────────────────────────────────────

export type FrameworkId =
  | "owasp_mcp"
  | "owasp_asi"
  | "cosai"
  | "maestro"
  | "eu_ai_act"
  | "mitre_atlas";

export const ALL_FRAMEWORKS: readonly FrameworkId[] = [
  "owasp_mcp",
  "owasp_asi",
  "cosai",
  "maestro",
  "eu_ai_act",
  "mitre_atlas",
] as const;

/** Human-readable framework metadata */
export interface FrameworkMetadata {
  id: FrameworkId;
  name: string;
  short_name: string;
  authority: string;
  reference_url: string;
}

// ─── Framework → Category → Control mapping ────────────────────────────────

/**
 * A single (framework, category, control) coordinate. A rule's `appliesTo`
 * is an array of these — one rule may map to many controls across many
 * frameworks (shared rules).
 */
export interface FrameworkControlMapping {
  framework: FrameworkId;
  /** e.g. "Article 14 — Human Oversight", "MCP01", "ASI09", "T2", "L6" */
  category: string;
  /** e.g. "Art.14", "MCP01", "ASI09", "T2.1", "L6.2", "AML.T0054" */
  control: string;
  /** Optional sub-control for fine-grained mapping */
  sub_control?: string;
  /**
   * Framework version pin — so a compliance report records *which*
   * revision of EU AI Act / OWASP MCP / etc. the rule was validated
   * against. Auditors need this for regulatory defensibility.
   */
  framework_version?: string;
}

// ─── Edge-case strategies ──────────────────────────────────────────────────

/**
 * The closed set of adversarial strategies the runtime test generator may
 * pick from. New strategies must be added to this enum AND documented in
 * `src/tests/edge-case-strategies.ts`. The LLM prompt is constructed from
 * the descriptions in that file — the LLM cannot invent strategies.
 */
export type EdgeCaseStrategy =
  | "unicode-evasion"
  | "encoding-bypass"
  | "privilege-chain"
  | "auth-bypass-window"
  | "consent-bypass"
  | "audit-erasure"
  | "boundary-leak"
  | "cross-tool-flow"
  | "trust-inversion"
  | "shadow-state"
  | "race-condition"
  | "config-drift"
  | "supply-chain-pivot"
  | "credential-laundering"
  | "human-oversight-bypass";

// ─── Evidence Bundle ───────────────────────────────────────────────────────

/**
 * Structured facts about the server, gathered deterministically before any
 * LLM call. The bundle is the ONLY thing the LLM sees about the server.
 *
 * Each rule produces its own bundle shape extending this base; specialized
 * fields go in the `findings` map keyed by a stable string id so the bundle
 * is JSON-serializable for the audit log.
 */
export interface EvidenceBundle {
  /** Stable id used for cache keys and audit log correlation */
  bundle_id: string;
  /** Rule that produced this bundle */
  rule_id: string;
  /** Server under analysis */
  server_id: string;
  /** Hash of the bundle contents (for cache keys) */
  content_hash: string;
  /** Top-level summary the rule wants to surface */
  summary: string;
  /** Structured fact map. Keys are domain-specific. Values must be JSON. */
  facts: Record<string, unknown>;
  /** Pointers into AnalysisContext (e.g. tool names, file paths, line numbers) */
  pointers: EvidencePointer[];
  /** Whether the deterministic gather phase already detected a violation */
  deterministic_violation: boolean;
  /** Temporal evidence — prior scans feeding longitudinal rules (rug-pull, drift) */
  temporal?: TemporalEvidence;
  /** Counterfactual probes — "what would change if we removed X?" causal tests */
  counterfactual_probes?: CounterfactualProbe[];
  /** Links to other rules' bundles that form an attack chain with this one */
  attack_chain_links?: AttackChainLink[];
  /** Signed provenance receipt for auditor replay */
  provenance?: ProvenanceReceipt;
  /** Uncertainty-aware severity dial — overrides the rule's static severity */
  computed_severity?: ComputedSeverity;
}

/** Prior observations used by temporal rules (rug-pull, drift) */
export interface TemporalEvidence {
  /** Window the history covers */
  window: { from: string; to: string };
  /** Summary facts per prior scan — rule-defined shape */
  prior_scans: Array<{
    scan_id: string;
    scanned_at: string;
    bundle_hash: string;
    summary: string;
  }>;
  /** Delta the rule cares about */
  delta_detected: boolean;
  delta_reason?: string;
}

/** Causal probe: what changes if we remove a specific evidence element? */
export interface CounterfactualProbe {
  probe_id: string;
  /** Evidence element removed from the bundle */
  removed: string;
  /** Whether the deterministic_violation still holds without it */
  still_violates: boolean;
  /** Rule-authored rationale explaining what this probe tests */
  rationale: string;
}

/** A link between two rules' bundles that together form a kill chain */
export interface AttackChainLink {
  link_id: string;
  linked_rule_id: string;
  /** Stage in the chain (1 = root cause, N = impact) */
  stage: number;
  /** Why this link is causal, not just co-occurring */
  causality_rationale: string;
}

/** Signed bundle receipt that enables offline replay */
export interface ProvenanceReceipt {
  /** sha256 over bundle content, scan_id, timestamp */
  receipt_hash: string;
  /** Rule charter SHA when the bundle was generated */
  charter_sha: string;
  /** Model id at time of synthesis/verdict (if LLM touched this bundle) */
  model_id?: string;
  /** Scan id that produced it */
  scan_id: string;
  /** ISO timestamp when the bundle was frozen */
  generated_at: string;
}

/** Computed severity = base × evidence_strength × blast_radius */
export interface ComputedSeverity {
  base: Severity;
  evidence_strength: number; // 0..1
  blast_radius: number; // 0..1 — how far exploitation propagates
  effective: Severity;
  rationale: string;
}

export interface EvidencePointer {
  /** What the pointer refers to */
  kind:
    | "tool"
    | "parameter"
    | "source-file"
    | "source-line"
    | "resource"
    | "prompt"
    | "root"
    | "capability"
    | "dependency"
    | "initialize-field";
  /** Human-readable label */
  label: string;
  /** Concrete location (tool name, file:line, dep name, etc.) */
  location: string;
  /** Short observed value (truncated for the audit log) */
  observed?: string;
}

// ─── Compliance Test ───────────────────────────────────────────────────────

/**
 * A single adversarial test. Tests are NOT pre-baked — they are synthesized
 * by the LLM at runtime from the evidence bundle and the rule's allowed
 * strategies. They live only for the duration of one scan.
 */
export interface ComplianceTest {
  /** Unique within a (server, rule) run */
  test_id: string;
  rule_id: string;
  /** Which strategy this test embodies */
  strategy: EdgeCaseStrategy;
  /** One-line hypothesis */
  hypothesis: string;
  /** Specific evidence path the test inspects */
  evidence_path: string;
  /** Concrete attack scenario in plain language */
  scenario: string;
  /** What signature in the bundle indicates a violation */
  expected_violation_signature: string;
  /** Why this is a critical edge case (forces the generator off "textbook") */
  criticality_justification: string;
}

/** The verdict from the LLM execution step (before judge re-validation) */
export interface RawTestResult {
  test_id: string;
  verdict: "fail" | "pass" | "inconclusive";
  rationale: string;
  /** Pointer into the evidence bundle that supports the verdict */
  evidence_path_used: string;
}

/** The verdict from the deterministic judge (the hallucination firewall) */
export interface JudgedTestResult extends RawTestResult {
  judge_confirmed: boolean;
  judge_rationale: string;
}

// ─── Compliance Finding ────────────────────────────────────────────────────

/**
 * A finding produced by a compliance rule. Backed by an `EvidenceChain` so
 * the existing chain renderer / scorer / DB layer can consume it without
 * special-casing.
 */
export interface ComplianceFinding {
  /** Unique id assigned at persistence time */
  id?: string;
  /** Server under analysis */
  server_id: string;
  /** Rule that produced the finding */
  rule_id: string;
  /** Which framework controls this finding satisfies */
  applies_to: FrameworkControlMapping[];
  severity: Severity;
  /** Uncertainty-aware computed severity (overrides `severity` for reporting) */
  computed_severity?: ComputedSeverity;
  /** The structured evidence chain (mandatory) */
  chain: EvidenceChain;
  /** The adversarial test that fired (linked back to compliance_agent_runs) */
  test: ComplianceTest;
  /** Judge result that confirmed the test */
  judge_result: JudgedTestResult;
  /** Remediation guidance from the rule */
  remediation: string;
  /**
   * Optional proof-carrying remediation — an executable-ish patch
   * (e.g. annotation additions, schema tweaks) the user can apply.
   */
  remediation_patch?: RemediationPatch;
  /** Confidence score (capped at 0.85 for LLM-derived findings) */
  confidence: number;
  /** Created timestamp (set by orchestrator) */
  created_at?: Date;
  /**
   * Outcome status — normally "non-compliant". "compliant-with-rationale" is
   * a *structured negative proof*: the rule ran, found nothing, and
   * deterministically attests that the server satisfies the control. These
   * are surfaced in reports so auditors see positive evidence, not just
   * gaps.
   */
  status?: FindingStatus;
}

export type FindingStatus = "non-compliant" | "compliant-with-rationale";

/** Patch payload — executable remediation, not just prose */
export interface RemediationPatch {
  /** The target artifact this patch applies to */
  target: "tool-annotation" | "output-schema" | "manifest" | "source-file" | "config";
  /** Human-readable title */
  title: string;
  /** The concrete change (plain-text diff or structured mutation) */
  mutation: string;
  /** Why applying this mutation will flip the finding to compliant */
  expected_effect: string;
}

// ─── Framework Agent ───────────────────────────────────────────────────────

/**
 * A framework agent owns a list of categories and the rules attached to each.
 * It does not run rules itself — the orchestrator does. The agent provides
 * the *taxonomy* the orchestrator dispatches against and the *report shape*
 * the reporter renders.
 */
export interface FrameworkAgentLike {
  readonly id: FrameworkId;
  readonly metadata: FrameworkMetadata;
  /** Ordered list of categories that make up the framework's structure */
  categories(): FrameworkCategory[];
  /** All rule ids this agent will run */
  ruleIds(): string[];
}

export interface FrameworkCategory {
  /** e.g. "Article 14 — Human Oversight" */
  name: string;
  /** e.g. "Art.14" */
  control: string;
  /** Plain-language description of what the category requires */
  description: string;
  /** Rule ids that fulfill this category */
  rule_ids: string[];
}

// ─── Compliance Report ─────────────────────────────────────────────────────

export interface ComplianceReport {
  framework: FrameworkId;
  framework_metadata: FrameworkMetadata;
  server_id: string;
  generated_at: Date;
  category_results: CategoryResult[];
  overall_status: "compliant" | "non-compliant" | "partial" | "insufficient-evidence";
  /** Independent compliance sub-score 0-100. Not added to total_score. */
  compliance_score: number;
  findings_count: number;
  llm_calls_made: number;
  cached_runs: number;
}

export interface CategoryResult {
  category: FrameworkCategory;
  status: "compliant" | "non-compliant" | "partial" | "insufficient-evidence";
  findings: ComplianceFinding[];
  /** Rules that ran but produced no findings (compliant evidence) */
  rules_clean: string[];
  /** Rules that were skipped due to missing data */
  rules_skipped: string[];
}

// ─── Orchestrator inputs ───────────────────────────────────────────────────

export interface ComplianceScanRequest {
  server_id: string;
  /** "all" or a specific list of frameworks */
  frameworks: FrameworkId[] | "all";
  /** When true, use the recorded LLM mocks under __tests__/llm-mocks/ */
  use_llm_mock?: boolean;
  /** Override the model id (default: claude-opus-4-6) */
  model?: string;
  /** Maximum tests to synthesize per rule (default: 5) */
  max_tests_per_rule?: number;
}

export interface ComplianceScanResult {
  scan_id: string;
  server_id: string;
  reports: ComplianceReport[];
  combined_findings: ComplianceFinding[];
  duration_ms: number;
  llm_calls_made: number;
  cached_runs: number;
}
