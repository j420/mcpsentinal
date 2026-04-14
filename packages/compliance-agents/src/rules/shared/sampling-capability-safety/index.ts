/**
 * Rule: sampling-capability-safety
 *
 * Detects the super-injection amplification loop (arXiv 2601.17549):
 * server declares sampling capability, ingests untrusted content, and
 * has no cost caps. Fully structural — walks declared capabilities,
 * capability graph, and source-file token hits.
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
  INGESTION_SOURCE_TOKENS,
  graphFor,
  makeBundle,
  sourceTokenHits,
  standardJudge,
} from "../../../rule-kit/index.js";

interface IngestionTool {
  tool_name: string;
  reasons: string[];
}

interface SamplingFacts {
  sampling_declared: boolean;
  sampling_capability: string;
  ingestion_tools: IngestionTool[];
  cost_caps_found: string[];
  ingestion_tokens_found: string[];
}

const METADATA: ComplianceRuleMetadata = {
  id: "shared-sampling-capability-safety",
  name: "Sampling Capability Safety",
  severity: "critical",
  intent:
    "A server MUST NOT combine the MCP sampling capability with untrusted-content ingestion unless it enforces structured cost caps and human-in-the-loop gates.",
  applies_to: [
    { framework: "owasp_mcp", category: "MCP01 — Prompt Injection", control: "MCP01" },
    { framework: "owasp_asi", category: "ASI01 — Agent Goal Hijack", control: "ASI01" },
    { framework: "owasp_asi", category: "ASI08 — Resource Exhaustion", control: "ASI08" },
    { framework: "cosai", category: "T4 — Prompt Injection", control: "T4" },
    { framework: "cosai", category: "T10 — Denial of Wallet", control: "T10" },
    { framework: "maestro", category: "L3 — Deployment Integrity", control: "L3" },
    { framework: "eu_ai_act", category: "Article 15 — Accuracy, Robustness, Cybersecurity", control: "Art.15" },
    { framework: "mitre_atlas", category: "AML.T0054 — LLM Prompt Injection", control: "AML.T0054" },
  ],
  threat_refs: [
    {
      id: "arXiv-2601.17549",
      title: "Sampling-amplified prompt injection in MCP",
      year: 2026,
      relevance: "Measured 23-41% injection amplification when sampling is combined with content ingestion.",
    },
    {
      id: "CVE-2025-SAMPLING",
      title: "MCP server sampling cost amplification",
      year: 2025,
      relevance: "Denial-of-wallet attack driving unbounded client-side inference spend via sampling.",
    },
    {
      id: "OWASP-ASI08",
      title: "OWASP Agentic Top 10 — Resource Exhaustion",
      relevance: "Names the denial-of-wallet failure class.",
    },
    {
      id: "MITRE-AML.T0054",
      title: "MITRE ATLAS LLM Prompt Injection",
      relevance: "Taxonomy anchor for the indirect injection attack path this rule prevents.",
    },
  ],
  strategies: ["cross-tool-flow", "boundary-leak", "shadow-state"],
  remediation:
    "Either remove the sampling capability declaration or add structured cost caps (max_tokens, token_budget, inferenceQuota) and gate every sampling call behind a human-in-the-loop confirmation. Separate ingestion tools into a different MCP server that does not declare sampling.",
};

class SamplingCapabilitySafetyRule extends ComplianceRule {
  readonly metadata = METADATA;

  gatherEvidence(context: AnalysisContext): EvidenceBundle {
    const declared = context.declared_capabilities ?? null;
    const samplingDeclared = Boolean(declared?.sampling);

    const graph = graphFor(context);
    const ingestionTools: IngestionTool[] = [];

    for (const node of graph.nodes) {
      const reasons: string[] = [];
      const ingestCap = node.capabilities.find(
        (c) => c.capability === "ingests-untrusted" && c.confidence >= 0.4,
      );
      const netCap = node.capabilities.find(
        (c) => c.capability === "receives-network" && c.confidence >= 0.4,
      );
      if (ingestCap) {
        reasons.push(`ingests-untrusted (${ingestCap.confidence.toFixed(2)})`);
      }
      if (netCap) {
        reasons.push(`receives-network (${netCap.confidence.toFixed(2)})`);
      }
      if (reasons.length > 0) {
        ingestionTools.push({ tool_name: node.name, reasons });
      }
    }

    const costCaps = sourceTokenHits(context, COST_CAP_MARKERS);
    const ingestionHits = sourceTokenHits(context, INGESTION_SOURCE_TOKENS);

    const pointers: EvidencePointer[] = [];
    if (samplingDeclared) {
      pointers.push({
        kind: "capability",
        label: "sampling capability declared",
        location: "sampling_capability",
        observed: "declared_capabilities.sampling=true",
      });
    }
    for (const tool of ingestionTools) {
      pointers.push({
        kind: "tool",
        label: "untrusted-content ingestion tool",
        location: `tool:${tool.tool_name}`,
        observed: tool.reasons.join("; "),
      });
    }
    if (costCaps.length === 0 && samplingDeclared) {
      pointers.push({
        kind: "source-file",
        label: "no cost-cap markers in source",
        location: "source_files",
        observed: "no max_tokens / token_budget / inferenceQuota detected",
      });
    }

    const deterministicViolation =
      samplingDeclared && ingestionTools.length > 0 && costCaps.length === 0;

    const facts: SamplingFacts = {
      sampling_declared: samplingDeclared,
      sampling_capability: "sampling_capability",
      ingestion_tools: ingestionTools,
      cost_caps_found: costCaps,
      ingestion_tokens_found: ingestionHits,
    };

    return makeBundle({
      rule_id: this.metadata.id,
      context,
      summary: deterministicViolation
        ? `Sampling+ingestion amplification loop without cost caps (${ingestionTools.length} ingestion tool(s))`
        : `Sampling declared=${samplingDeclared}, ingestion tools=${ingestionTools.length}, cost caps=${costCaps.length}`,
      facts: facts as unknown as Record<string, unknown>,
      pointers,
      deterministic_violation: deterministicViolation,
    });
  }

  judge(bundle: EvidenceBundle, raw: RawTestResult): JudgedTestResult {
    const facts = bundle.facts as unknown as SamplingFacts;
    const deterministicNames: string[] = [];
    if (facts.sampling_declared) {
      deterministicNames.push("sampling_capability");
    }
    for (const tool of facts.ingestion_tools ?? []) {
      deterministicNames.push(tool.tool_name);
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

export const samplingCapabilitySafetyRule = new SamplingCapabilitySafetyRule();
