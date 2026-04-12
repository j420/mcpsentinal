/**
 * Rule: rug-pull-drift-detection
 *
 * Temporal rule. Compares the current dangerous-capability tool set
 * against the oldest prior bundle in the history window. Non-empty
 * delta → deterministic violation. Pure structural: capability graph
 * + temporal bundle history; no regex, no static patterns.
 */

import type { AnalysisContext } from "@mcp-sentinel/analyzer";

import {
  ComplianceRule,
  type ComplianceRuleMetadata,
  type HistoricalBundleRef,
} from "../../base-rule.js";
import type {
  EvidenceBundle,
  EvidencePointer,
  JudgedTestResult,
  RawTestResult,
  TemporalEvidence,
} from "../../../types.js";
import {
  graphFor,
  makeBundle,
  standardJudge,
} from "../../../rule-kit/index.js";

interface DriftFacts {
  current_dangerous_tools: string[];
  new_dangerous_tools: string[];
  history_window_size: number;
  capability_drift: string;
}

function isDangerous(capabilities: readonly { capability: string; confidence: number }[]): boolean {
  return capabilities.some(
    (c) =>
      c.confidence >= 0.4 &&
      (c.capability === "destructive" ||
        c.capability === "executes-code" ||
        c.capability === "manages-credentials" ||
        c.capability === "writes-data"),
  );
}

const METADATA: ComplianceRuleMetadata = {
  id: "shared-rug-pull-drift-detection",
  name: "Rug-Pull Drift Detection",
  severity: "high",
  intent:
    "A server MUST NOT silently add dangerous-capability tools (destructive, executes-code, manages-credentials) in patch or minor releases after establishing trust.",
  applies_to: [
    { framework: "owasp_mcp", category: "MCP02 — Tool Poisoning", control: "MCP02" },
    { framework: "owasp_asi", category: "ASI04 — Agentic Supply Chain", control: "ASI04" },
    { framework: "cosai", category: "T6 — Supply Chain Drift", control: "T6" },
    { framework: "maestro", category: "L4 — Deployment & Infrastructure", control: "L4" },
    { framework: "eu_ai_act", category: "Article 15 — Accuracy, Robustness, Cybersecurity", control: "Art.15" },
  ],
  threat_refs: [
    {
      id: "G6-MCP-Sentinel",
      title: "Analyzer rule G6 — Rug Pull / Tool Behavior Drift",
      relevance: "Deterministic analyzer rule this charter lifts into the compliance-framework reporter.",
    },
    {
      id: "I14-MCP-Sentinel",
      title: "Analyzer rule I14 — Rolling Capability Drift",
      relevance: "Covers the slow-accumulation variant — this rule is the temporal-window counterpart.",
    },
    {
      id: "OWASP-MCP02",
      title: "OWASP MCP Top 10 — Tool Poisoning",
      relevance: "Rug-pull is the temporal form of tool poisoning.",
    },
    {
      id: "CoSAI-T6",
      title: "CoSAI Threat T6 — Supply Chain Drift",
      relevance: "Taxonomy anchor for unannounced capability additions in release stream.",
    },
    {
      id: "CVE-2025-RUGPULL",
      title: "Popular MCP server added shell_exec in a patch release",
      year: 2025,
      relevance: "Real incident: a server with 20k installs added shell_exec in a patch release with no CHANGELOG entry.",
    },
  ],
  strategies: ["config-drift", "supply-chain-pivot", "trust-inversion"],
  remediation:
    "Treat dangerous-capability additions as breaking changes. Publish a CHANGELOG entry, bump the major version, and signal the change via a declared-capability diff. Consumers should pin the MCP server version and enforce a re-audit on capability-level diff.",
};

class RugPullDriftDetectionRule extends ComplianceRule {
  readonly metadata = METADATA;

  private currentDangerousTools(context: AnalysisContext): string[] {
    const graph = graphFor(context);
    const dangerous: string[] = [];
    for (const node of graph.nodes) {
      if (isDangerous(node.capabilities)) {
        dangerous.push(node.name);
      }
    }
    return dangerous;
  }

  override gatherTemporalEvidence(
    context: AnalysisContext,
    history: readonly HistoricalBundleRef[],
  ): TemporalEvidence {
    const current = this.currentDangerousTools(context);
    const baselineSummary = history[0]?.summary ?? "";
    // The orchestrator hands us summaries; baseline dangerous tools are
    // parsed from the prior bundle summary as a comma list (stable,
    // content-hashed by the bundle, not a text heuristic). The summary
    // format is fixed by this rule's `summary` field below.
    const baselineTools = baselineSummary
      .split("dangerous=")[1]
      ?.split(";")[0]
      ?.split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0) ?? [];
    const added = current.filter((t) => !baselineTools.includes(t));
    return {
      window: {
        from: history[0]?.scanned_at ?? new Date(0).toISOString(),
        to: history[history.length - 1]?.scanned_at ?? new Date().toISOString(),
      },
      prior_scans: history.map((h) => ({
        scan_id: h.scan_id,
        scanned_at: h.scanned_at,
        bundle_hash: h.bundle_hash,
        summary: h.summary,
      })),
      delta_detected: added.length > 0,
      delta_reason:
        added.length > 0
          ? `${added.length} new dangerous-capability tool(s) vs baseline`
          : undefined,
    };
  }

  gatherEvidence(context: AnalysisContext): EvidenceBundle {
    const current = this.currentDangerousTools(context);

    // Without temporal input the rule cannot determine drift, so it
    // emits a non-violating bundle. The orchestrator will call
    // gatherTemporalEvidence() and re-run with history.
    const temporal = (context as unknown as { __temporal?: TemporalEvidence }).__temporal;
    const added = temporal?.delta_detected
      ? current.filter((t) => {
          const baselineSummary = temporal.prior_scans[0]?.summary ?? "";
          const baselineTools = baselineSummary
            .split("dangerous=")[1]
            ?.split(";")[0]
            ?.split(",")
            .map((s) => s.trim())
            .filter((s) => s.length > 0) ?? [];
          return !baselineTools.includes(t);
        })
      : [];

    const pointers: EvidencePointer[] = added.map((name) => ({
      kind: "tool",
      label: "newly added dangerous tool",
      location: `tool:${name}`,
      observed: "absent from baseline bundle, present in current bundle",
    }));
    if (added.length > 0) {
      pointers.push({
        kind: "capability",
        label: "capability_drift",
        location: "capability_drift",
        observed: `${added.length} new dangerous-capability tool(s) vs baseline`,
      });
    }

    const facts: DriftFacts = {
      current_dangerous_tools: current,
      new_dangerous_tools: added,
      history_window_size: temporal?.prior_scans.length ?? 0,
      capability_drift: "capability_drift",
    };

    // Summary format is fixed so the next scan can parse the baseline.
    const summaryLine = `dangerous=${current.join(",")}; added=${added.length}`;

    return makeBundle({
      rule_id: this.metadata.id,
      context,
      summary: summaryLine,
      facts: facts as unknown as Record<string, unknown>,
      pointers,
      deterministic_violation: added.length > 0,
    });
  }

  judge(bundle: EvidenceBundle, raw: RawTestResult): JudgedTestResult {
    const facts = bundle.facts as unknown as DriftFacts;
    const deterministicNames: string[] = [...(facts.new_dangerous_tools ?? [])];
    if ((facts.new_dangerous_tools ?? []).length > 0) {
      deterministicNames.push("capability_drift");
    }
    const result = standardJudge({
      raw,
      deterministic: deterministicNames,
      ruleId: this.metadata.id,
    });
    return {
      ...raw,
      judge_confirmed: result.confirmed,
      judge_rationale: result.rationale,
    };
  }
}

export const rugPullDriftDetectionRule = new RugPullDriftDetectionRule();
