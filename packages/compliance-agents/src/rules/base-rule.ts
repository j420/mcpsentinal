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
  EdgeCaseStrategy,
  EvidenceBundle,
  FrameworkControlMapping,
  JudgedTestResult,
  RawTestResult,
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

/**
 * Stable bundle id helper. Cache key for compliance_test_cache uses this.
 * The hash is content-addressed: the same evidence bundle produces the
 * same id, so re-runs against an unchanged server hit the cache.
 */
export function makeBundleId(ruleId: string, serverId: string, contentHash: string): string {
  return `${ruleId}::${serverId}::${contentHash}`;
}
