/**
 * Rule: inference-cost-attack-surface
 *
 * Targets the LLM-specific denial-of-wallet surface. A server declaring
 * sampling or exposing executor tools that trigger inference without
 * structural cost caps (max_tokens / token_budget / inferenceQuota) is
 * a deterministic Art.15 / ASI08 violation.
 *
 * Pure structural: declared_capabilities + capability graph + source
 * token hits. No regex, no static payloads.
 */

import type { AnalysisContext } from "@mcp-sentinel/analyzer";

import {
  ComplianceRule,
  type ComplianceRuleMetadata,
} from "../../base-rule.js";
import type {
  EvidenceBundle,
  EvidencePointer,
  JudgedTestResult,
  RawTestResult,
} from "../../../types.js";
import {
  COST_CAP_MARKERS,
  graphFor,
  makeBundle,
  sourceTokenHits,
  standardJudge,
} from "../../../rule-kit/index.js";

interface InferenceSink {
  tool_name: string;
  rationale: string;
}

interface InferenceCostFacts {
  sampling_declared: boolean;
  inference_sinks: InferenceSink[];
  cost_caps_found: string[];
  inference_cost: string;
}

const METADATA: ComplianceRuleMetadata = {
  id: "shared-inference-cost-attack-surface",
  name: "Inference Cost Attack Surface",
  severity: "medium",
  intent:
    "A server that triggers LLM inference (sampling, executor loops, recursive planner tools) MUST declare structural cost caps so a single call cannot drive unbounded client-side inference spend.",
  applies_to: [
    { framework: "owasp_asi", category: "ASI08 — Resource Exhaustion", control: "ASI08" },
    { framework: "cosai", category: "T10 — Denial of Wallet", control: "T10" },
    { framework: "maestro", category: "L4 — Deployment & Infrastructure", control: "L4" },
    { framework: "eu_ai_act", category: "Article 15 — Accuracy, Robustness, Cybersecurity", control: "Art.15" },
  ],
  threat_refs: [
    {
      id: "CVE-2025-WALLET",
      title: "Denial-of-wallet attack on MCP sampling client",
      year: 2025,
      relevance: "Single malicious call drove $10k of inference spend in four hours against an MCP sampling client with no cost caps.",
    },
    {
      id: "OWASP-ASI08",
      title: "OWASP Agentic Top 10 — Resource Exhaustion",
      relevance: "Names the denial-of-wallet failure class this rule structurally prevents.",
    },
    {
      id: "MCP-Spec-2025-06-18",
      title: "MCP sampling capability specification",
      year: 2025,
      relevance: "The sampling capability was standardized without a cost-cap contract — this rule enforces the missing contract.",
    },
  ],
  strategies: ["race-condition", "boundary-leak", "cross-tool-flow"],
  remediation:
    "Add structured cost caps to every inference path (max_tokens, token_budget, inferenceQuota). Set timeouts on every inference call. Cap recursion depth on planner-style tools. Prefer streaming with early-abort semantics over unbounded context returns.",
};

class InferenceCostAttackSurfaceRule extends ComplianceRule {
  readonly metadata = METADATA;

  gatherEvidence(context: AnalysisContext): EvidenceBundle {
    const declared = context.declared_capabilities ?? null;
    const samplingDeclared = Boolean(declared?.sampling);

    const graph = graphFor(context);
    const inferenceSinks: InferenceSink[] = [];

    for (const node of graph.nodes) {
      const execCap = node.capabilities.find(
        (c) => c.capability === "executes-code" && c.confidence >= 0.4,
      );
      const sendCap = node.capabilities.find(
        (c) => c.capability === "sends-network" && c.confidence >= 0.4,
      );
      const parts: string[] = [];
      if (execCap) {
        parts.push(`executes-code (${execCap.confidence.toFixed(2)})`);
      }
      if (sendCap && samplingDeclared) {
        parts.push(`sends-network (${sendCap.confidence.toFixed(2)}) + sampling`);
      }
      if (parts.length > 0) {
        inferenceSinks.push({
          tool_name: node.name,
          rationale: parts.join("; "),
        });
      }
    }

    const costCaps = sourceTokenHits(context, COST_CAP_MARKERS);

    const pointers: EvidencePointer[] = [];
    if (samplingDeclared) {
      pointers.push({
        kind: "capability",
        label: "sampling capability declared",
        location: "sampling_capability",
        observed: "declared_capabilities.sampling=true",
      });
    }
    for (const sink of inferenceSinks) {
      pointers.push({
        kind: "tool",
        label: "inference sink tool",
        location: `tool:${sink.tool_name}`,
        observed: sink.rationale,
      });
    }
    if (costCaps.length === 0 && (samplingDeclared || inferenceSinks.length > 0)) {
      pointers.push({
        kind: "source-file",
        label: "inference_cost",
        location: "source_files",
        observed: "no max_tokens / token_budget / inferenceQuota detected",
      });
    }

    const deterministicViolation =
      inferenceSinks.length > 0 &&
      costCaps.length === 0 &&
      samplingDeclared;

    const facts: InferenceCostFacts = {
      sampling_declared: samplingDeclared,
      inference_sinks: inferenceSinks,
      cost_caps_found: costCaps,
      inference_cost: "inference_cost",
    };

    return makeBundle({
      rule_id: this.metadata.id,
      context,
      summary: deterministicViolation
        ? `${inferenceSinks.length} inference sink(s) without cost caps under declared sampling`
        : `Sampling declared=${samplingDeclared}, sinks=${inferenceSinks.length}, cost caps=${costCaps.length}`,
      facts: facts as unknown as Record<string, unknown>,
      pointers,
      deterministic_violation: deterministicViolation,
    });
  }

  judge(bundle: EvidenceBundle, raw: RawTestResult): JudgedTestResult {
    const facts = bundle.facts as unknown as InferenceCostFacts;
    const deterministicNames: string[] = [];
    for (const sink of facts.inference_sinks ?? []) {
      deterministicNames.push(sink.tool_name);
    }
    if ((facts.cost_caps_found ?? []).length === 0 && (facts.inference_sinks ?? []).length > 0) {
      deterministicNames.push("inference_cost");
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

export const inferenceCostAttackSurfaceRule =
  new InferenceCostAttackSurfaceRule();
