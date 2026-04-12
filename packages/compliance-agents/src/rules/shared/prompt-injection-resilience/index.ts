/**
 * Rule: prompt-injection-resilience
 * Author personas: Senior MCP Threat Researcher (CHARTER.md) +
 *                  Senior MCP Security Engineer (this file).
 *
 * Detection strategy:
 *   1. Build the analyzer's capability graph and select tools whose
 *      classification includes `ingests-untrusted`.
 *   2. For each ingestion sink, inspect the analyzer's tool metadata
 *      for a structural untrusted-content boundary: an output schema
 *      that discriminates `model_message` from `untrusted_content`,
 *      OR a sanitizer annotation key.
 *   3. Bundle the unbounded sinks. The judge verifies any LLM verdict
 *      against `facts.unbounded_ingestion_sinks`.
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

interface IngestionSink {
  tool_name: string;
  reasons: string[];
  has_output_schema: boolean;
  has_content_type_discriminator: boolean;
  has_sanitizer_annotation: boolean;
}

interface PIResilienceFacts {
  unbounded_ingestion_sinks: IngestionSink[];
  bounded_ingestion_sinks: IngestionSink[];
  total_tools: number;
}

const SANITIZER_ANNOTATION_KEYS: readonly string[] = [
  "untrustedContent",
  "sanitized",
  "contentBoundary",
];

const METADATA: ComplianceRuleMetadata = {
  id: "shared-prompt-injection-resilience",
  name: "Prompt Injection Resilience on Untrusted Ingestion",
  severity: "critical",
  intent:
    "Every tool that ingests untrusted external content MUST declare a structural boundary between trusted instructions and untrusted data.",
  applies_to: [
    {
      framework: "owasp_mcp",
      category: "MCP01 — Prompt Injection",
      control: "MCP01",
    },
    {
      framework: "owasp_asi",
      category: "ASI01 — Agent Goal Hijack",
      control: "ASI01",
    },
    {
      framework: "cosai",
      category: "T4 — Prompt Injection",
      control: "T4",
    },
    {
      framework: "maestro",
      category: "L3 — Agent Frameworks",
      control: "L3",
    },
    {
      framework: "mitre_atlas",
      category: "AML.T0054 — LLM Prompt Injection",
      control: "AML.T0054",
      sub_control: "AML.T0054.001",
    },
  ],
  threat_refs: [
    {
      id: "EMBRACE-THE-RED-INDIRECT",
      title: "Embrace The Red — Indirect Prompt Injection in MCP",
      url: "https://embracethered.com/blog/",
      year: 2024,
      relevance:
        "Demonstrated end-to-end exploitation of MCP servers ingesting web content with no boundary.",
    },
    {
      id: "INVARIANT-LABS-PI-2025",
      title: "Invariant Labs — MCP indirect injection paper",
      year: 2025,
      relevance:
        "Quantitative study showing the boundary-less ingestion pattern is the dominant exploit primitive.",
    },
    {
      id: "MITRE-ATLAS-T0054-001",
      title: "AML.T0054.001 — Indirect Prompt Injection technique",
      url: "https://atlas.mitre.org/techniques/AML.T0054.001",
      relevance:
        "Codifies the technique class this rule structurally prevents.",
    },
  ],
  strategies: ["boundary-leak", "cross-tool-flow", "trust-inversion"],
  remediation:
    "For every tool that ingests untrusted content, declare an output schema with a `content_type` discriminator separating `model_message` from `untrusted_content`. Document the boundary in the description and ensure downstream tools never re-emit `untrusted_content` without re-tagging.",
};

class PromptInjectionResilienceRule extends ComplianceRule {
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

    const unbounded: IngestionSink[] = [];
    const bounded: IngestionSink[] = [];
    const pointers: EvidencePointer[] = [];

    for (const node of graph.nodes) {
      const ingestionCap = node.capabilities.find(
        (c) => c.capability === "ingests-untrusted" && c.confidence >= 0.4,
      );
      if (!ingestionCap) continue;

      const tool = tools.find((t) => t.name === node.name);
      const outputSchema = (tool?.output_schema ?? null) as Record<string, unknown> | null;
      const ann = (tool?.annotations ?? {}) as Record<string, unknown>;

      const hasOutputSchema = outputSchema !== null;
      const hasContentTypeDiscriminator = checkContentTypeDiscriminator(outputSchema);
      const hasSanitizerAnnotation = SANITIZER_ANNOTATION_KEYS.some(
        (k) => ann[k] === true || typeof ann[k] === "string",
      );

      const sink: IngestionSink = {
        tool_name: node.name,
        reasons: [
          `capability=ingests-untrusted (confidence ${ingestionCap.confidence.toFixed(2)})`,
        ],
        has_output_schema: hasOutputSchema,
        has_content_type_discriminator: hasContentTypeDiscriminator,
        has_sanitizer_annotation: hasSanitizerAnnotation,
      };

      pointers.push({
        kind: "tool",
        label: `ingestion sink: ${node.name}`,
        location: `tool:${node.name}`,
        observed: sink.reasons.join("; "),
      });

      if (hasContentTypeDiscriminator || hasSanitizerAnnotation) {
        bounded.push(sink);
      } else {
        unbounded.push(sink);
      }
    }

    const facts: PIResilienceFacts = {
      unbounded_ingestion_sinks: unbounded,
      bounded_ingestion_sinks: bounded,
      total_tools: tools.length,
    };

    const summary =
      unbounded.length > 0
        ? `${unbounded.length} ingestion sink(s) lack a structural untrusted-content boundary`
        : `All ingestion sinks bounded (${bounded.length})`;

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
      deterministic_violation: unbounded.length > 0,
    };
  }

  judge(bundle: EvidenceBundle, raw: RawTestResult): JudgedTestResult {
    const facts = bundle.facts as unknown as PIResilienceFacts;
    const sinks = facts.unbounded_ingestion_sinks ?? [];

    if (raw.verdict !== "fail") {
      return {
        ...raw,
        judge_confirmed: false,
        judge_rationale: `Judge rejects non-fail verdict (${raw.verdict}).`,
      };
    }
    if (sinks.length === 0) {
      return {
        ...raw,
        judge_confirmed: false,
        judge_rationale:
          "Judge rejects: no unbounded ingestion sinks were detected by the deterministic gather. Hallucination.",
      };
    }
    const referenced = sinks.find((s) => raw.evidence_path_used.includes(s.tool_name));
    if (!referenced) {
      return {
        ...raw,
        judge_confirmed: false,
        judge_rationale: `Judge rejects: evidence_path_used (${raw.evidence_path_used}) does not reference any deterministic sink (${sinks.map((s) => s.tool_name).join(", ")}).`,
      };
    }
    return {
      ...raw,
      judge_confirmed: true,
      judge_rationale: `Judge confirms: tool '${referenced.tool_name}' ingests untrusted content with no content-type discriminator or sanitizer annotation.`,
    };
  }
}

/**
 * Inspect a tool's output schema for a discriminated union that separates
 * trusted model_message from untrusted_content. We do this by walking the
 * schema object — NO regex.
 */
function checkContentTypeDiscriminator(
  schema: Record<string, unknown> | null,
): boolean {
  if (!schema || typeof schema !== "object") return false;
  // Look for `oneOf` / `anyOf` with `content_type` property in branches.
  const branches = (schema.oneOf ?? schema.anyOf) as unknown[] | undefined;
  if (!Array.isArray(branches)) return false;
  let sawTrusted = false;
  let sawUntrusted = false;
  for (const branch of branches) {
    if (!branch || typeof branch !== "object") continue;
    const props = (branch as Record<string, unknown>).properties as
      | Record<string, unknown>
      | undefined;
    if (!props || typeof props !== "object") continue;
    const ctype = props.content_type as Record<string, unknown> | undefined;
    if (!ctype) continue;
    const constValue = ctype.const;
    if (constValue === "model_message" || constValue === "trusted") sawTrusted = true;
    if (constValue === "untrusted_content" || constValue === "untrusted") sawUntrusted = true;
  }
  return sawTrusted && sawUntrusted;
}

export const promptInjectionResilienceRule = new PromptInjectionResilienceRule();
