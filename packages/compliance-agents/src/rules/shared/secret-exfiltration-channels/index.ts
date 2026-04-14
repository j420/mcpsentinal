/**
 * Rule: secret-exfiltration-channels
 *
 * Detects the structural secret-leak channel: any server that
 * co-exposes secret/private-data readers with network sender tools
 * without a trust boundary marker. Walks the capability graph and
 * builds the cross-product of (reader × sender) pairs.
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
  CONSENT_MARKER_KEYS,
  graphFor,
  makeBundle,
  standardJudge,
} from "../../../rule-kit/index.js";

interface LeakPair {
  tool_name: string;
  partner_tool: string;
  pair_rationale: string;
  pair_annotated: boolean;
}

interface LeakFacts {
  leak_pairs: LeakPair[];
  secret_reader_count: number;
  network_sender_count: number;
}

const METADATA: ComplianceRuleMetadata = {
  id: "shared-secret-exfiltration-channels",
  name: "Secret Exfiltration Channels",
  severity: "critical",
  intent:
    "A server MUST NOT co-expose tools that read secrets or private data with tools that send data to the network without a declared trust boundary.",
  applies_to: [
    { framework: "owasp_mcp", category: "MCP04 — Data Exfiltration", control: "MCP04" },
    { framework: "owasp_asi", category: "ASI06 — Memory & Context Poisoning", control: "ASI06" },
    { framework: "cosai", category: "T5 — Data Exfiltration", control: "T5" },
    { framework: "maestro", category: "L2 — Data Operations", control: "L2" },
    { framework: "eu_ai_act", category: "Article 15 — Accuracy, Robustness, Cybersecurity", control: "Art.15" },
    { framework: "mitre_atlas", category: "AML.T0057 — LLM Data Leakage", control: "AML.T0057" },
  ],
  threat_refs: [
    {
      id: "OWASP-MCP04",
      title: "OWASP MCP Top 10 — Data Exfiltration",
      relevance: "Names the failure class this rule structurally prevents.",
    },
    {
      id: "MITRE-AML.T0057",
      title: "MITRE ATLAS LLM Data Leakage",
      relevance: "Taxonomy anchor for the AI-mediated data leak attack pattern.",
    },
    {
      id: "OWASP-ASI06",
      title: "OWASP Agentic Top 10 — Memory & Context Poisoning",
      relevance: "Adjacent propagation vector the exfiltration chain exploits.",
    },
    {
      id: "InvariantLabs-2025-MCP04",
      title: "Production MCP exfiltration chain",
      year: 2025,
      relevance: "Real-world documented leak via co-exposed reader/sender tools.",
    },
  ],
  strategies: ["credential-laundering", "boundary-leak", "cross-tool-flow"],
  remediation:
    "Split secret-handling tools from network-sending tools across separate MCP servers. Add a trustBoundary annotation that forbids forwarding private data. Use a centralized secrets manager with a deny-by-default outbound policy. Gate outbound calls in mixed-capability tools with human-in-the-loop confirmation.",
};

class SecretExfiltrationChannelsRule extends ComplianceRule {
  readonly metadata = METADATA;

  gatherEvidence(context: AnalysisContext): EvidenceBundle {
    const graph = graphFor(context);

    const secretReaders: string[] = [];
    const networkSenders: string[] = [];
    const annotationMap: Record<string, boolean> = {};

    for (const node of graph.nodes) {
      const caps = node.capabilities.map((c) => c.capability);
      const isSecret =
        caps.includes("manages-credentials") || caps.includes("reads-private-data");
      const isSender = caps.includes("sends-network");

      const annotations =
        (context.tools ?? []).find((t) => t.name === node.name)?.annotations ??
        {};
      const annotated = CONSENT_MARKER_KEYS.some(
        (key) => typeof (annotations as Record<string, unknown>)[key] !== "undefined",
      );
      annotationMap[node.name] = annotated;

      if (isSecret) secretReaders.push(node.name);
      if (isSender) networkSenders.push(node.name);
    }

    const pairs: LeakPair[] = [];
    for (const reader of secretReaders) {
      for (const sender of networkSenders) {
        if (reader === sender) {
          pairs.push({
            tool_name: reader,
            partner_tool: sender,
            pair_rationale: "single tool reads secrets and sends network",
            pair_annotated: annotationMap[reader] ?? false,
          });
        } else {
          pairs.push({
            tool_name: reader,
            partner_tool: sender,
            pair_rationale: "co-exposed reader/sender pair",
            pair_annotated: (annotationMap[reader] ?? false) && (annotationMap[sender] ?? false),
          });
        }
      }
    }

    const unmitigated = pairs.filter((p) => !p.pair_annotated);

    const pointers: EvidencePointer[] = [];
    for (const pair of unmitigated) {
      pointers.push({
        kind: "tool",
        label: pair.pair_rationale,
        location: `tool:${pair.tool_name}`,
        observed: `partner=${pair.partner_tool}`,
      });
    }

    const facts: LeakFacts = {
      leak_pairs: unmitigated,
      secret_reader_count: secretReaders.length,
      network_sender_count: networkSenders.length,
    };

    return makeBundle({
      rule_id: this.metadata.id,
      context,
      summary:
        unmitigated.length > 0
          ? `${unmitigated.length} unmitigated secret→network leak pair(s)`
          : `secret readers=${secretReaders.length}, network senders=${networkSenders.length}, all pairs annotated`,
      facts: facts as unknown as Record<string, unknown>,
      pointers,
      deterministic_violation: unmitigated.length > 0,
    });
  }

  judge(bundle: EvidenceBundle, raw: RawTestResult): JudgedTestResult {
    const facts = bundle.facts as unknown as LeakFacts;
    const result = standardJudge({
      raw,
      deterministic: facts.leak_pairs ?? [],
      ruleId: this.metadata.id,
    });
    return {
      ...raw,
      judge_confirmed: result.confirmed,
      judge_rationale: result.rationale,
    };
  }
}

export const secretExfiltrationChannelsRule =
  new SecretExfiltrationChannelsRule();
