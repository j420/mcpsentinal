/**
 * Rule: cross-framework-kill-chain
 *
 * Composes individual structural signals (ingestion, amplifier, egress)
 * into an explicit three-stage kill chain. No new primitives — purely
 * structural co-occurrence detection over the capability graph, with
 * attack_chain_links pointing at companion rules whose bundles share
 * the chain.
 */

import type { AnalysisContext } from "@mcp-sentinel/analyzer";

import {
  ComplianceRule,
  type ComplianceRuleMetadata,
} from "../../base-rule.js";
import type {
  AttackChainLink,
  EvidenceBundle,
  EvidencePointer,
  JudgedTestResult,
  RawTestResult,
} from "../../../types.js";
import {
  CONSENT_MARKER_KEYS,
  graphFor,
  makeBundle,
  standardJudge,
} from "../../../rule-kit/index.js";

interface StageTools {
  ingestion: string[];
  amplifier: string[];
  egress: string[];
}

interface KillChainFacts {
  kill_chain_matched: boolean;
  kill_chain: string;
  stage_tools: StageTools;
  sampling_declared: boolean;
}

const METADATA: ComplianceRuleMetadata = {
  id: "shared-cross-framework-kill-chain",
  name: "Cross-Framework Kill Chain",
  severity: "critical",
  intent:
    "A server MUST NOT host all three stages of a prompt-injection kill chain (ingestion → amplifier → egress) in a single MCP configuration. Breaking any stage breaks the chain.",
  applies_to: [
    { framework: "owasp_mcp", category: "MCP01 — Prompt Injection", control: "MCP01" },
    { framework: "owasp_asi", category: "ASI06 — Memory & Context Poisoning", control: "ASI06" },
    { framework: "cosai", category: "T5 — Data Exfiltration", control: "T5" },
    { framework: "maestro", category: "L3 — Deployment Integrity", control: "L3" },
    { framework: "eu_ai_act", category: "Article 15 — Accuracy, Robustness, Cybersecurity", control: "Art.15" },
    { framework: "mitre_atlas", category: "AML.T0057 — LLM Data Leakage", control: "AML.T0057" },
  ],
  threat_refs: [
    {
      id: "F1-MCP-Sentinel",
      title: "Analyzer rule F1 — Lethal Trifecta",
      relevance: "Deterministic analyzer rule; this compliance rule composes the same structural facts into an explicit kill chain with cross-framework mapping.",
    },
    {
      id: "arXiv-2601.17549",
      title: "Sampling-amplified prompt injection in MCP",
      year: 2026,
      relevance: "Measured 23-41% injection amplification when sampling is combined with content ingestion — the Stage 2 amplifier.",
    },
    {
      id: "OWASP-MCP01",
      title: "OWASP MCP Top 10 — Prompt Injection",
      relevance: "Names the failure class the chain exploits.",
    },
    {
      id: "OWASP-ASI06",
      title: "OWASP Agentic Top 10 — Memory & Context Poisoning",
      relevance: "Covers the injection → persistence propagation the chain enables.",
    },
    {
      id: "MITRE-AML.T0057",
      title: "MITRE ATLAS LLM Data Leakage",
      relevance: "The impact stage — exfiltration via egress tools after the amplifier stage.",
    },
    {
      id: "Invariant-2026-CHAIN",
      title: "Cross-framework kill-chain incident",
      year: 2026,
      relevance: "Documented real-world incident: web ingestion tool → sampling → slack send in a single MCP config, $6k exfiltration in 40 minutes.",
    },
  ],
  strategies: ["cross-tool-flow", "credential-laundering", "trust-inversion"],
  remediation:
    "Break at least one stage of the chain. Move the ingestion tool to a separate MCP server with no network egress, disable sampling or add inferenceQuota + consent gate, or add consent markers to every network-sender tool. Fixing any single stage breaks the chain.",
};

class CrossFrameworkKillChainRule extends ComplianceRule {
  readonly metadata = METADATA;

  gatherEvidence(context: AnalysisContext): EvidenceBundle {
    const graph = graphFor(context);
    const tools = context.tools ?? [];
    const samplingDeclared = Boolean(context.declared_capabilities?.sampling);

    const ingestion: string[] = [];
    const amplifier: string[] = [];
    const egress: string[] = [];

    for (const node of graph.nodes) {
      const caps = node.capabilities;
      const has = (name: string) =>
        caps.some((c) => c.capability === name && c.confidence >= 0.4);

      if (has("ingests-untrusted") || has("receives-network")) {
        ingestion.push(node.name);
      }
      if (has("executes-code")) {
        amplifier.push(node.name);
      }
      if (has("sends-network")) {
        const tool = tools.find((t) => t.name === node.name);
        const annotations = (tool?.annotations ?? {}) as Record<string, unknown>;
        const gated = CONSENT_MARKER_KEYS.some(
          (k) => annotations[k] === true,
        );
        if (!gated) {
          egress.push(node.name);
        }
      }
    }

    if (samplingDeclared && amplifier.length === 0) {
      amplifier.push("sampling_capability");
    }

    const killChainMatched =
      ingestion.length > 0 && amplifier.length > 0 && egress.length > 0;

    const pointers: EvidencePointer[] = [];
    for (const name of ingestion) {
      pointers.push({
        kind: "tool",
        label: "stage1 ingestion",
        location: `tool:${name}`,
        observed: "ingests-untrusted or receives-network",
      });
    }
    for (const name of amplifier) {
      pointers.push({
        kind: name === "sampling_capability" ? "capability" : "tool",
        label: "stage2 amplifier",
        location: name === "sampling_capability" ? "sampling_capability" : `tool:${name}`,
        observed: name === "sampling_capability" ? "declared_capabilities.sampling=true" : "executes-code",
      });
    }
    for (const name of egress) {
      pointers.push({
        kind: "tool",
        label: "stage3 egress (unconsented)",
        location: `tool:${name}`,
        observed: "sends-network with no consent marker",
      });
    }

    const facts: KillChainFacts = {
      kill_chain_matched: killChainMatched,
      kill_chain: "kill_chain",
      stage_tools: { ingestion, amplifier, egress },
      sampling_declared: samplingDeclared,
    };

    return makeBundle({
      rule_id: this.metadata.id,
      context,
      summary: killChainMatched
        ? `Three-stage kill chain: ${ingestion.length} ingestion, ${amplifier.length} amplifier, ${egress.length} egress`
        : `Partial chain: ingestion=${ingestion.length}, amplifier=${amplifier.length}, egress=${egress.length}`,
      facts: facts as unknown as Record<string, unknown>,
      pointers,
      deterministic_violation: killChainMatched,
    });
  }

  override attackChainLinks(bundle: EvidenceBundle): AttackChainLink[] {
    const facts = bundle.facts as unknown as KillChainFacts;
    if (!facts.kill_chain_matched) return [];
    return [
      {
        link_id: `${bundle.bundle_id}::stage1`,
        linked_rule_id: "shared-prompt-injection-resilience",
        stage: 1,
        causality_rationale:
          "Stage 1 (ingestion) aligns with prompt-injection-resilience — untrusted content enters the context.",
      },
      {
        link_id: `${bundle.bundle_id}::stage2`,
        linked_rule_id: "shared-sampling-capability-safety",
        stage: 2,
        causality_rationale:
          "Stage 2 (amplifier) aligns with sampling-capability-safety — injected content is amplified by an execution or sampling loop.",
      },
      {
        link_id: `${bundle.bundle_id}::stage3`,
        linked_rule_id: "shared-secret-exfiltration-channels",
        stage: 3,
        causality_rationale:
          "Stage 3 (egress) aligns with secret-exfiltration-channels — amplified content leaves the trust boundary via an unconsented network sender.",
      },
    ];
  }

  judge(bundle: EvidenceBundle, raw: RawTestResult): JudgedTestResult {
    const facts = bundle.facts as unknown as KillChainFacts;
    const deterministicNames: string[] = [];
    if (facts.kill_chain_matched) {
      deterministicNames.push("kill_chain");
      for (const name of facts.stage_tools?.ingestion ?? []) deterministicNames.push(name);
      for (const name of facts.stage_tools?.amplifier ?? []) deterministicNames.push(name);
      for (const name of facts.stage_tools?.egress ?? []) deterministicNames.push(name);
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

export const crossFrameworkKillChainRule = new CrossFrameworkKillChainRule();
