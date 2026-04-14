/**
 * Rule: mitre-aml-t0058-context-poisoning
 * Author personas: Senior MCP Threat Researcher (CHARTER.md) +
 *                  Senior MCP Security Engineer (this file).
 *
 * Detection strategy:
 *   1. Build the capability graph and inspect its detected cycles
 *      (`graph.cycles`) — these are the F6-shaped read/write loops.
 *   2. For each cycle, check whether the read-back tools surface
 *      provenance metadata (output_schema with `provenance` /
 *      `trust_class` properties).
 *   3. Bundle cycles that lack provenance.
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

interface ContextPoisoningLoop {
  cycle: string[];
  reasons: string[];
  reader_lacks_provenance: string[];
}

interface ContextPoisoningFacts {
  context_poisoning_loops: ContextPoisoningLoop[];
  total_tools: number;
}

const PROVENANCE_KEYS: readonly string[] = [
  "provenance",
  "trust_class",
  "source_identity",
  "authored_by",
];

const METADATA: ComplianceRuleMetadata = {
  id: "mitre-aml-t0058-context-poisoning",
  name: "MITRE ATLAS AML.T0058 — AI Agent Context Poisoning",
  severity: "critical",
  intent:
    "Read/write loops over the same persistent backend MUST surface provenance metadata to the agent.",
  applies_to: [
    {
      framework: "mitre_atlas",
      category: "AML.T0058 — AI Agent Context Poisoning",
      control: "AML.T0058",
    },
  ],
  threat_refs: [
    {
      id: "MITRE-AML-T0058",
      title: "MITRE ATLAS AML.T0058 — AI Agent Context Poisoning",
      url: "https://atlas.mitre.org/techniques/AML.T0058",
      relevance: "Direct technique mapping.",
    },
    {
      id: "EMBRACE-THE-RED-MEMORY-2024",
      title: "Embrace The Red — Persistent Memory Poisoning of Claude",
      year: 2024,
      relevance:
        "Demonstrates the read/write loop exploitation this rule structurally detects.",
    },
    {
      id: "MCP-SENTINEL-F6",
      title: "MCP Sentinel rule F6 — Circular Data Loop",
      relevance:
        "Existing deterministic detector whose graph cycle output we reuse as the evidence substrate.",
    },
  ],
  strategies: ["shadow-state", "cross-tool-flow", "trust-inversion"],
  remediation:
    "Tag every persisted record with provenance metadata (creator identity, timestamp, trust class). Read-back tools MUST surface the metadata to the model and refuse records lacking a trust class. Provide a default trust filter that excludes self-authored and externally authored records.",
};

class MitreAMLT0058ContextPoisoningRule extends ComplianceRule {
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

    const loops: ContextPoisoningLoop[] = [];
    const pointers: EvidencePointer[] = [];

    for (const cycle of graph.cycles) {
      const readers = cycle.filter((toolName) => {
        const node = graph.nodes.find((n) => n.name === toolName);
        if (!node) return false;
        return node.capabilities.some(
          (c) =>
            (c.capability === "reads-private-data" && c.confidence >= 0.4) ||
            (c.capability === "reads-public-data" && c.confidence >= 0.4),
        );
      });

      const lacksProvenance = readers.filter((toolName) => {
        const tool = tools.find((t) => t.name === toolName);
        return !hasProvenanceInOutputSchema(tool?.output_schema ?? null);
      });

      if (lacksProvenance.length === 0) continue;

      loops.push({
        cycle,
        reasons: [
          `cycle: ${cycle.join(" → ")}`,
          `${lacksProvenance.length} reader(s) lack provenance metadata in output_schema`,
        ],
        reader_lacks_provenance: lacksProvenance,
      });
      for (const t of cycle) {
        pointers.push({
          kind: "tool",
          label: `context-poisoning loop participant`,
          location: `tool:${t}`,
          observed: `cycle: ${cycle.join(" → ")}`,
        });
      }
    }

    const facts: ContextPoisoningFacts = {
      context_poisoning_loops: loops,
      total_tools: tools.length,
    };

    const summary =
      loops.length > 0
        ? `${loops.length} read/write loop(s) lack provenance — context-poisoning surface`
        : `No context-poisoning loops detected`;

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
      deterministic_violation: loops.length > 0,
    };
  }

  judge(bundle: EvidenceBundle, raw: RawTestResult): JudgedTestResult {
    const facts = bundle.facts as unknown as ContextPoisoningFacts;
    const loops = facts.context_poisoning_loops ?? [];

    if (raw.verdict !== "fail") {
      return {
        ...raw,
        judge_confirmed: false,
        judge_rationale: `Judge rejects non-fail verdict (${raw.verdict}).`,
      };
    }
    if (loops.length === 0) {
      return {
        ...raw,
        judge_confirmed: false,
        judge_rationale: "Judge rejects: no context-poisoning loops in deterministic gather.",
      };
    }
    const ref = loops.find((l) =>
      l.cycle.some((tool) => raw.evidence_path_used.includes(tool)),
    );
    if (!ref) {
      return {
        ...raw,
        judge_confirmed: false,
        judge_rationale: `Judge rejects: evidence_path_used (${raw.evidence_path_used}) does not reference any cycle participant.`,
      };
    }
    return {
      ...raw,
      judge_confirmed: true,
      judge_rationale: `Judge confirms: cycle '${ref.cycle.join(" → ")}' has reader(s) without provenance: ${ref.reader_lacks_provenance.join(", ")}.`,
    };
  }
}

function hasProvenanceInOutputSchema(
  schema: Record<string, unknown> | null,
): boolean {
  if (!schema || typeof schema !== "object") return false;
  const props = (schema.properties ?? {}) as Record<string, unknown>;
  if (typeof props !== "object" || props === null) return false;
  return PROVENANCE_KEYS.some((k) => k in props);
}

export const mitreAMLT0058ContextPoisoningRule = new MitreAMLT0058ContextPoisoningRule();
