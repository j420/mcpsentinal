/**
 * ComplianceRule — base class for every rule in the compliance-agents package.
 *
 * The dual-persona protocol (see CLAUDE.md):
 *   1. Senior MCP Threat Researcher writes CHARTER.md next to the rule
 *   2. Senior MCP Security Engineer implements this class
 *
 * Three deterministic methods are MANDATORY:
 *   - gatherEvidence(context) → EvidenceBundle
 *   - testStrategies()        → which adversarial strategies the LLM may use
 *   - judge(bundle, verdict)  → re-validate the LLM verdict (hallucination firewall)
 *
 * Forbidden inside any rule file under src/rules/:
 *   - Regex literals (/.../)
 *   - new RegExp(...)
 *   - String-literal arrays longer than 5 entries
 *   The no-static-patterns CI guard fails the build if any of these slip in.
 */

import type { AnalysisContext } from "@mcp-sentinel/analyzer";
import type { Severity } from "@mcp-sentinel/database";
import type {
  AttackChainLink,
  ComputedSeverity,
  CounterfactualProbe,
  EdgeCaseStrategy,
  EvidenceBundle,
  FrameworkControlMapping,
  JudgedTestResult,
  RawTestResult,
  RemediationPatch,
  TemporalEvidence,
} from "../types.js";

export interface ComplianceRuleMetadata {
  id: string;
  name: string;
  severity: Severity;
  /** Plain-language summary of what the rule asserts about the server */
  intent: string;
  /** All (framework, category, control) tuples this rule satisfies */
  applies_to: FrameworkControlMapping[];
  /** At least one CVE/paper/incident — empty array fails CI */
  threat_refs: ThreatRef[];
  /** Strategies the runtime test generator may use */
  strategies: EdgeCaseStrategy[];
  /** What the human should do to fix a failing finding */
  remediation: string;
}

export interface ThreatRef {
  id: string;
  title: string;
  url?: string;
  year?: number;
  /** How this reference relates to the rule */
  relevance: string;
}

export abstract class ComplianceRule {
  abstract readonly metadata: ComplianceRuleMetadata;

  /**
   * Phase 1: Deterministic evidence gathering. Walks AnalysisContext using
   * the analyzer's structural toolkits and produces a typed bundle of facts.
   *
   * Implementations MUST NOT use regex literals or hard-coded string lists.
   * Use AST queries, capability-graph traversal, entropy, similarity, etc.
   */
  abstract gatherEvidence(context: AnalysisContext): EvidenceBundle;

  /**
   * Phase 4: Deterministic re-validation of the LLM verdict.
   *
   * This is the hallucination firewall. The LLM may declare a violation,
   * but the finding is suppressed unless `judge()` agrees based on the
   * structural evidence in the bundle.
   *
   * Returns a JudgedTestResult — `judge_confirmed=false` causes the
   * orchestrator to drop the finding entirely.
   */
  abstract judge(bundle: EvidenceBundle, raw: RawTestResult): JudgedTestResult;

  /**
   * Convenience accessor — exposes the metadata's strategies. Subclasses
   * may override to provide context-aware strategy selection (e.g. only
   * `human-oversight-bypass` if the bundle has destructive sinks).
   */
  testStrategies(_bundle: EvidenceBundle): EdgeCaseStrategy[] {
    return this.metadata.strategies;
  }

  /**
   * Optional Phase 1b: temporal evidence.
   *
   * Rules that reason over history (rug-pull drift, capability drift,
   * score-history anomaly) override this to fetch prior scans from the
   * temporal store. Pure structural rules leave it as undefined.
   */
  gatherTemporalEvidence?(
    context: AnalysisContext,
    history: readonly HistoricalBundleRef[],
  ): TemporalEvidence;

  /**
   * Optional Phase 1c: counterfactual probing.
   *
   * "If I remove X from the bundle, does the deterministic violation still
   * hold?" Establishes causal attribution so reporters can explain *why*
   * the rule fired, not just that it did.
   */
  probeCounterfactual?(bundle: EvidenceBundle): CounterfactualProbe[];

  /**
   * Optional Phase 4b: uncertainty-aware severity computation.
   *
   * Default behaviour uses `metadata.severity`. Rules with context-sensitive
   * impact (e.g. destructive sink with 1 vs 10 downstream consumers) can
   * override to compute effective severity from evidence strength and
   * blast radius.
   */
  computeSeverity?(bundle: EvidenceBundle): ComputedSeverity;

  /**
   * Optional Phase 4c: structured negative proof.
   *
   * When the rule runs and finds no violation, this produces a signed
   * "compliant-with-rationale" attestation. Auditors get positive evidence
   * that the control is satisfied, not just the absence of a finding.
   */
  attestCompliant?(bundle: EvidenceBundle): CompliantAttestation | undefined;

  /**
   * Optional Phase 4d: proof-carrying remediation.
   *
   * When a finding fires, rules can produce an executable patch the user
   * can apply — annotation addition, schema tweak, manifest edit — not
   * just English prose.
   */
  remediationPatch?(bundle: EvidenceBundle): RemediationPatch | undefined;

  /**
   * Optional Phase 4e: attack-chain linkage.
   *
   * Returns links to other rules' bundles that, together with this one,
   * form a full kill chain. The cross-framework-kill-chain rule uses
   * these to synthesize multi-step attack narratives.
   */
  attackChainLinks?(bundle: EvidenceBundle): AttackChainLink[];

  /**
   * Convenience: does this rule apply to a given framework?
   * Used by the orchestrator when computing the rule union.
   */
  appliesToFramework(framework: string): boolean {
    return this.metadata.applies_to.some((m) => m.framework === framework);
  }

  /**
   * Convenience: get all controls this rule covers within a framework.
   */
  controlsForFramework(framework: string): FrameworkControlMapping[] {
    return this.metadata.applies_to.filter((m) => m.framework === framework);
  }
}

/** Reference to a previously persisted bundle — shape used by temporal hooks */
export interface HistoricalBundleRef {
  scan_id: string;
  scanned_at: string;
  bundle_hash: string;
  summary: string;
}

/** Structured negative proof surfaced in reports when a rule runs clean */
export interface CompliantAttestation {
  rule_id: string;
  attestation: string;
  evidence_summary: string;
  /** Which control(s) this attestation satisfies */
  controls_satisfied: FrameworkControlMapping[];
}

/**
 * Stable bundle id helper. Cache key for compliance_test_cache uses this.
 * The hash is content-addressed: the same evidence bundle produces the
 * same id, so re-runs against an unchanged server hit the cache.
 */
export function makeBundleId(ruleId: string, serverId: string, contentHash: string): string {
  return `${ruleId}::${serverId}::${contentHash}`;
}
