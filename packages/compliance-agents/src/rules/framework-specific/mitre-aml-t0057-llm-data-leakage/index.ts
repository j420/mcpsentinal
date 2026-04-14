/**
 * Rule: mitre-aml-t0057-llm-data-leakage
 *
 * Structural cross-product of private-data readers × network senders
 * framed in MITRE ATLAS AML.T0057 taxonomy.
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
import { graphFor, makeBundle, standardJudge } from "../../../rule-kit/index.js";

interface LeakagePair {
  reader: string;
  sender: string;
  reader_capability: string;
}

interface LeakageFacts {
  leakage_pairs: LeakagePair[];
  llm_data_leakage: string;
}

const METADATA: ComplianceRuleMetadata = {
  id: "mitre-aml-t0057-llm-data-leakage",
  name: "MITRE ATLAS AML.T0057 — LLM Data Leakage",
  severity: "critical",
  intent:
    "A server MUST NOT co-host a private-data reader (reads-private-data or manages-credentials) with a network sender (sends-network) without a structural redaction boundary between them.",
  applies_to: [
    {
      framework: "mitre_atlas",
      category: "AML.T0057 — LLM Data Leakage",
      control: "AML.T0057",
    },
    {
      framework: "owasp_mcp",
      category: "MCP04 — Data Exfiltration",
      control: "MCP04",
    },
  ],
  threat_refs: [
    {
      id: "MITRE-AML.T0057",
      title: "MITRE ATLAS AML.T0057 — LLM Data Leakage",
      relevance: "Canonical technique this rule is scoped to.",
    },
    {
      id: "OWASP-MCP04",
      title: "OWASP MCP Top 10 — Data Exfiltration",
      relevance: "Names the failure class this rule structurally prevents.",
    },
    {
      id: "CVE-2025-LEAK",
      title: "MCP server returned /etc/shadow via tool response",
      year: 2025,
      relevance: "Real incident where private-data reader + network sender in the same server leaked OS credentials.",
    },
  ],
  strategies: ["credential-laundering", "cross-tool-flow", "boundary-leak"],
  remediation:
    "Redact private data at the source tool before it enters tool responses. Add a structural redaction layer and ensure no network sender can observe raw private-data responses. Split readers and senders into separate MCP servers with no shared memory.",
};

class MitreAMLT0057LLMDataLeakageRule extends ComplianceRule {
  readonly metadata = METADATA;

  gatherEvidence(context: AnalysisContext): EvidenceBundle {
    const graph = graphFor(context);

    const readers: Array<{ name: string; capability: string }> = [];
    const senders: string[] = [];
    for (const node of graph.nodes) {
      const caps = node.capabilities;
      const priv = caps.find(
        (c) => c.confidence >= 0.4 && (c.capability === "reads-private-data" || c.capability === "manages-credentials"),
      );
      if (priv) {
        readers.push({ name: node.name, capability: priv.capability });
      }
      if (caps.some((c) => c.capability === "sends-network" && c.confidence >= 0.4)) {
        senders.push(node.name);
      }
    }

    const pairs: LeakagePair[] = [];
    for (const reader of readers) {
      for (const sender of senders) {
        if (reader.name === sender) continue;
        pairs.push({
          reader: reader.name,
          sender,
          reader_capability: reader.capability,
        });
      }
    }

    const pointers: EvidencePointer[] = pairs.map((p) => ({
      kind: "tool",
      label: "AML.T0057 leakage pair",
      location: `${p.reader}→${p.sender}`,
      observed: `${p.reader_capability} → sends-network`,
    }));

    const facts: LeakageFacts = {
      leakage_pairs: pairs,
      llm_data_leakage: "llm_data_leakage",
    };

    return makeBundle({
      rule_id: this.metadata.id,
      context,
      summary:
        pairs.length > 0
          ? `${pairs.length} AML.T0057 leakage pair(s) (readers=${readers.length}, senders=${senders.length})`
          : `No AML.T0057 leakage pairs (readers=${readers.length}, senders=${senders.length})`,
      facts: facts as unknown as Record<string, unknown>,
      pointers,
      deterministic_violation: pairs.length > 0,
    });
  }

  judge(bundle: EvidenceBundle, raw: RawTestResult): JudgedTestResult {
    const facts = bundle.facts as unknown as LeakageFacts;
    const deterministicNames: string[] = [];
    for (const pair of facts.leakage_pairs ?? []) {
      deterministicNames.push(pair.reader);
      deterministicNames.push(pair.sender);
    }
    if ((facts.leakage_pairs ?? []).length > 0) {
      deterministicNames.push("llm_data_leakage");
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

export const mitreAMLT0057LLMDataLeakageRule =
  new MitreAMLT0057LLMDataLeakageRule();
