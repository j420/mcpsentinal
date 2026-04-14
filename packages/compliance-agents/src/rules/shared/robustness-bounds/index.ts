/**
 * Rule: robustness-bounds
 *
 * Detects servers that expose high-throughput or recursive tools
 * without any rate-limit / circuit-breaker library markers. Pure
 * structural: capability graph + source-file token hits.
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
  RATE_LIMIT_MARKERS,
  graphFor,
  makeBundle,
  sourceTokenHits,
  standardJudge,
} from "../../../rule-kit/index.js";

interface UnboundedTool {
  tool_name: string;
  rationale: string;
}

interface RobustnessFacts {
  unbounded_tools: UnboundedTool[];
  rate_limit_markers_found: string[];
  total_tools: number;
  robustness_bounds: boolean;
}

const HIGH_TOOL_COUNT_THRESHOLD = 20;

const METADATA: ComplianceRuleMetadata = {
  id: "shared-robustness-bounds",
  name: "Robustness Bounds",
  severity: "high",
  intent:
    "A server MUST declare structural robustness bounds (rate limits, timeouts, circuit breakers, concurrency caps) to satisfy EU AI Act Article 15 robustness requirements.",
  applies_to: [
    { framework: "owasp_asi", category: "ASI08 — Resource Exhaustion", control: "ASI08" },
    { framework: "cosai", category: "T10 — Denial of Service", control: "T10" },
    { framework: "maestro", category: "L4 — Deployment & Infrastructure", control: "L4" },
    { framework: "eu_ai_act", category: "Article 15 — Accuracy, Robustness, Cybersecurity", control: "Art.15" },
  ],
  threat_refs: [
    {
      id: "OWASP-ASI08",
      title: "OWASP Agentic Top 10 — Resource Exhaustion",
      relevance: "Names the failure class this rule structurally prevents.",
    },
    {
      id: "CoSAI-T10",
      title: "CoSAI Threat T10 — Denial of Service / Wallet",
      relevance: "Taxonomy anchor for the resource-exhaustion attack surface.",
    },
    {
      id: "EU-AI-Act-Art15",
      title: "EU AI Act Article 15 — Robustness & Cybersecurity",
      relevance: "Regulatory baseline requiring robustness bounds for high-risk AI systems.",
    },
    {
      id: "CVE-2025-ROBUST",
      title: "Unbounded recursion DoS in MCP server",
      year: 2025,
      relevance: "Documented production outage caused by missing robustness bounds.",
    },
  ],
  strategies: ["race-condition", "boundary-leak", "config-drift"],
  remediation:
    "Import a rate-limit / circuit-breaker library (rate-limiter-flexible, bottleneck, p-limit, opossum, cockatiel). Enforce timeouts on all network calls. Add recursion depth guards on any tool that can invoke itself transitively.",
};

class RobustnessBoundsRule extends ComplianceRule {
  readonly metadata = METADATA;

  gatherEvidence(context: AnalysisContext): EvidenceBundle {
    const graph = graphFor(context);
    const markers = sourceTokenHits(context, RATE_LIMIT_MARKERS);
    const hasBounds = markers.length > 0;
    const totalTools = graph.nodes.length;

    const unbounded: UnboundedTool[] = [];
    for (const node of graph.nodes) {
      const caps = node.capabilities.map((c) => c.capability);
      const highRisk =
        caps.includes("executes-code") ||
        caps.includes("sends-network") ||
        caps.includes("receives-network");
      if (!highRisk) continue;
      if (hasBounds) continue;
      unbounded.push({
        tool_name: node.name,
        rationale: `high-throughput caps=${caps.join("+")} and no rate-limit markers in source`,
      });
    }

    // Surface-area trigger: large tool count with no bounds at all.
    const surfaceTrigger = totalTools >= HIGH_TOOL_COUNT_THRESHOLD && !hasBounds;

    const pointers: EvidencePointer[] = [];
    for (const tool of unbounded) {
      pointers.push({
        kind: "tool",
        label: "high-throughput tool with no robustness bounds",
        location: `tool:${tool.tool_name}`,
        observed: tool.rationale,
      });
    }
    if (surfaceTrigger) {
      pointers.push({
        kind: "capability",
        label: "robustness_bounds",
        location: `tool_count:${totalTools}`,
        observed: `exceeds threshold ${HIGH_TOOL_COUNT_THRESHOLD} with no rate-limit markers`,
      });
    }

    const deterministicViolation = unbounded.length > 0 || surfaceTrigger;

    const facts: RobustnessFacts = {
      unbounded_tools: unbounded,
      rate_limit_markers_found: markers,
      total_tools: totalTools,
      robustness_bounds: hasBounds,
    };

    return makeBundle({
      rule_id: this.metadata.id,
      context,
      summary: deterministicViolation
        ? `${unbounded.length} unbounded tool(s)${surfaceTrigger ? " + large surface" : ""}, no rate-limit markers`
        : `Rate-limit markers: ${markers.length}, tools: ${totalTools}`,
      facts: facts as unknown as Record<string, unknown>,
      pointers,
      deterministic_violation: deterministicViolation,
    });
  }

  judge(bundle: EvidenceBundle, raw: RawTestResult): JudgedTestResult {
    const facts = bundle.facts as unknown as RobustnessFacts;
    const deterministicNames: string[] = [];
    for (const tool of facts.unbounded_tools ?? []) {
      deterministicNames.push(tool.tool_name);
    }
    if (!facts.robustness_bounds && (facts.total_tools ?? 0) >= HIGH_TOOL_COUNT_THRESHOLD) {
      deterministicNames.push("robustness_bounds");
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

export const robustnessBoundsRule = new RobustnessBoundsRule();
