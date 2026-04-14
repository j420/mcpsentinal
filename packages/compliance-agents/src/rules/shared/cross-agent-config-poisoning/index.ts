/**
 * Rule: cross-agent-config-poisoning
 * Author personas: Senior MCP Threat Researcher (CHARTER.md) +
 *                  Senior MCP Security Engineer (this file).
 *
 * Detection strategy:
 *   1. Capability graph identifies tools that both `accesses-filesystem`
 *      and `writes-data`.
 *   2. Inspect declared roots — any with URI broader than the server's
 *      working directory is flagged.
 *   3. Schema-inference style walk over parameters to find unconstrained
 *      `file_path` semantic params (no enum, no maxLength).
 *   4. Bundle the broad filesystem writers. The judge re-validates.
 */

import {
  buildCapabilityGraph,
  type AnalysisContext,
} from "@mcp-sentinel/analyzer";
import { createHash } from "node:crypto";

import {
  ComplianceRule,
  makeBundleId,
  type ComplianceRuleMetadata,
} from "../../base-rule.js";
import type {
  EvidenceBundle,
  EvidencePointer,
  JudgedTestResult,
  RawTestResult,
} from "../../../types.js";

interface BroadFilesystemWriter {
  tool_name: string;
  reasons: string[];
  unconstrained_path_params: string[];
}

interface CrossAgentFacts {
  broad_filesystem_writers: BroadFilesystemWriter[];
  broad_root_uris: string[];
  total_tools: number;
}

const METADATA: ComplianceRuleMetadata = {
  id: "shared-cross-agent-config-poisoning",
  name: "Cross-Agent Configuration Poisoning",
  severity: "critical",
  intent:
    "No tool MAY have unconstrained filesystem-write reach beyond the server's own containment root.",
  applies_to: [
    {
      framework: "owasp_mcp",
      category: "MCP10 — Supply Chain",
      control: "MCP10",
    },
    {
      framework: "owasp_asi",
      category: "ASI04 — Agentic Supply Chain",
      control: "ASI04",
    },
    {
      framework: "cosai",
      category: "T6 — Supply Chain Tampering",
      control: "T6",
    },
    {
      framework: "maestro",
      category: "L7 — Agent Ecosystem",
      control: "L7",
    },
    {
      framework: "mitre_atlas",
      category: "AML.T0060 — Modify AI Agent Configuration",
      control: "AML.T0060",
    },
  ],
  threat_refs: [
    {
      id: "EMBRACE-THE-RED-CROSSAGENT-2025",
      title: "Embrace The Red — Cross-agent config poisoning in MCP",
      year: 2025,
      relevance:
        "Live chain demonstrating workstation-wide compromise via cross-agent config writes.",
    },
    {
      id: "CVE-2025-53773",
      title: "CVE-2025-53773 — GitHub Copilot RCE via cross-agent injection",
      year: 2025,
      relevance:
        "CVE proving the threat model is exploitable in production AI tooling.",
    },
    {
      id: "MITRE-AML-T0060",
      title: "MITRE ATLAS AML.T0060 — Modify AI Agent Configuration",
      url: "https://atlas.mitre.org/techniques/AML.T0060",
      relevance: "Codifies the technique class.",
    },
  ],
  strategies: ["config-drift", "supply-chain-pivot", "privilege-chain"],
  remediation:
    "Constrain every filesystem-writing tool to a containment root the server controls. Never declare `/` or `~` as a root. Resolve paths and verify they begin with the containment root after symlink resolution.",
};

const BROAD_ROOT_URIS: readonly string[] = ["file:///", "file://~", "file://~/"];

class CrossAgentConfigPoisoningRule extends ComplianceRule {
  readonly metadata = METADATA;

  gatherEvidence(context: AnalysisContext): EvidenceBundle {
    const tools = context.tools ?? [];
    const graph = buildCapabilityGraph(
      tools.map((t) => ({
        name: t.name,
        description: t.description,
        input_schema: t.input_schema,
        annotations: t.annotations ?? null,
      })),
    );

    const broadRootUris: string[] = [];
    for (const root of context.roots ?? []) {
      if (BROAD_ROOT_URIS.some((u) => root.uri === u || root.uri.startsWith(u))) {
        broadRootUris.push(root.uri);
      }
    }

    const broad: BroadFilesystemWriter[] = [];
    const pointers: EvidencePointer[] = [];

    for (const node of graph.nodes) {
      const isFsWriter =
        node.capabilities.some(
          (c) => c.capability === "accesses-filesystem" && c.confidence >= 0.5,
        ) &&
        node.capabilities.some(
          (c) =>
            (c.capability === "writes-data" && c.confidence >= 0.5) ||
            (c.capability === "destructive" && c.confidence >= 0.4),
        );
      if (!isFsWriter) continue;

      // Inspect parameter constraints to find unconstrained path params.
      const unconstrained: string[] = [];
      for (const ch of node.input_channels) {
        if (ch.semantic !== "file_path") continue;
        const tool = tools.find((t) => t.name === node.name);
        const props = (tool?.input_schema?.properties ?? {}) as Record<
          string,
          Record<string, unknown>
        >;
        const param = props[ch.name] ?? {};
        if (!param.enum && !param.pattern && !param.maxLength) {
          unconstrained.push(ch.name);
        }
      }

      if (unconstrained.length === 0 && broadRootUris.length === 0) {
        continue;
      }

      const reasons: string[] = [];
      if (unconstrained.length > 0) {
        reasons.push(`unconstrained file_path params: ${unconstrained.join(", ")}`);
      }
      if (broadRootUris.length > 0) {
        reasons.push(`server declares broad roots: ${broadRootUris.join(", ")}`);
      }

      broad.push({
        tool_name: node.name,
        reasons,
        unconstrained_path_params: unconstrained,
      });
      pointers.push({
        kind: "tool",
        label: `broad filesystem writer: ${node.name}`,
        location: `tool:${node.name}`,
        observed: reasons.join("; "),
      });
    }

    const facts: CrossAgentFacts = {
      broad_filesystem_writers: broad,
      broad_root_uris: broadRootUris,
      total_tools: tools.length,
    };

    const summary =
      broad.length > 0
        ? `${broad.length} tool(s) can write outside a contained root — cross-agent poisoning surface`
        : `No broad filesystem writers detected`;

    const factsJson = JSON.stringify(facts);
    const contentHash = createHash("sha256")
      .update(`${context.server.id}::${factsJson}`)
      .digest("hex")
      .slice(0, 16);

    return {
      bundle_id: makeBundleId(this.metadata.id, context.server.id, contentHash),
      rule_id: this.metadata.id,
      server_id: context.server.id,
      content_hash: contentHash,
      summary,
      facts: facts as unknown as Record<string, unknown>,
      pointers,
      deterministic_violation: broad.length > 0,
    };
  }

  judge(bundle: EvidenceBundle, raw: RawTestResult): JudgedTestResult {
    const facts = bundle.facts as unknown as CrossAgentFacts;
    const writers = facts.broad_filesystem_writers ?? [];

    if (raw.verdict !== "fail") {
      return {
        ...raw,
        judge_confirmed: false,
        judge_rationale: `Judge rejects non-fail verdict (${raw.verdict}).`,
      };
    }
    if (writers.length === 0) {
      return {
        ...raw,
        judge_confirmed: false,
        judge_rationale: "Judge rejects: no broad filesystem writers in deterministic gather.",
      };
    }
    const ref = writers.find((w) => raw.evidence_path_used.includes(w.tool_name));
    if (!ref) {
      return {
        ...raw,
        judge_confirmed: false,
        judge_rationale: `Judge rejects: evidence_path_used (${raw.evidence_path_used}) does not reference any deterministic writer.`,
      };
    }
    return {
      ...raw,
      judge_confirmed: true,
      judge_rationale: `Judge confirms: tool '${ref.tool_name}' writes filesystem with unconstrained path scope (${ref.reasons.join("; ")}).`,
    };
  }
}

export const crossAgentConfigPoisoningRule = new CrossAgentConfigPoisoningRule();
