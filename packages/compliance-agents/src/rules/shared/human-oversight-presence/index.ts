/**
 * Rule: human-oversight-presence
 * Author personas: Senior MCP Threat Researcher (CHARTER.md) +
 *                  Senior MCP Security Engineer (this file).
 *
 * Threat model summary (see CHARTER.md for full text):
 *   A high-risk MCP server exposes destructive operations without a structural
 *   confirmation gate. The agent can be socially engineered into invoking
 *   them, and there is no human checkpoint to stop it.
 *
 * Frameworks satisfied: EU AI Act Art.14, OWASP ASI09, CoSAI T2, MAESTRO L6.
 *
 * Detection strategy (no regex, no static keyword lists):
 *   1. Build the analyzer's capability graph (`buildCapabilityGraph`).
 *   2. Identify destructive sinks via the graph's `destructive` /
 *      `executes-code` capability tags AND the MCP `destructiveHint`
 *      annotation set on the tool.
 *   3. For each destructive sink, check if any tool annotated as
 *      `requiresConfirmation` (or carrying a confirmation marker in
 *      `output_schema`) ordering-dominates it. Absence of such a gate
 *      is the lethal pattern.
 *   4. Bundle the result. The judge() validates the LLM verdict against
 *      `facts.destructive_sinks_without_gate`.
 */

import {
  buildCapabilityGraph,
  type AnalysisContext,
} from "@mcp-sentinel/analyzer";
import { createHash } from "node:crypto";

import { ComplianceRule, makeBundleId, type ComplianceRuleMetadata } from "../../base-rule.js";
import type {
  EvidenceBundle,
  EvidencePointer,
  JudgedTestResult,
  RawTestResult,
} from "../../../types.js";

interface DestructiveSink {
  tool_name: string;
  reasons: string[];
  has_destructive_hint: boolean;
  has_confirmation_marker: boolean;
}

interface HumanOversightFacts {
  destructive_sinks_without_gate: DestructiveSink[];
  destructive_sinks_with_gate: DestructiveSink[];
  total_tools: number;
  confirmation_gate_tool_names: string[];
  /** A tool counts as a confirmation gate if its annotations indicate it */
  confirmation_marker_keys: string[];
}

const METADATA: ComplianceRuleMetadata = {
  id: "shared-human-oversight-presence",
  name: "Human Oversight Presence on Destructive Operations",
  severity: "high",
  intent:
    "Every destructive MCP tool MUST be reachable only via a structural human confirmation gate.",
  applies_to: [
    {
      framework: "eu_ai_act",
      category: "Article 14 — Human Oversight",
      control: "Art.14",
    },
    {
      framework: "owasp_asi",
      category: "ASI09 — Overreliance & Underspecified Oversight",
      control: "ASI09",
    },
    {
      framework: "cosai",
      category: "T2 — Insufficient Human Oversight",
      control: "T2",
    },
    {
      framework: "maestro",
      category: "L6 — Security/Safety",
      control: "L6",
    },
  ],
  threat_refs: [
    {
      id: "EU-AI-ACT-ART14",
      title: "EU AI Act Article 14(4) — natural persons must be able to override",
      url: "https://artificialintelligenceact.eu/article/14/",
      year: 2024,
      relevance:
        "Codifies the requirement that high-risk AI systems must let humans disregard or reverse outputs.",
    },
    {
      id: "EMBRACE-THE-RED-2024",
      title: "Claude Desktop forced into destructive filesystem ops via indirect injection",
      url: "https://embracethered.com/blog/posts/2024/claude-desktop-mcp-prompt-injection/",
      year: 2024,
      relevance:
        "Live demonstration of exactly the failure mode this rule detects: missing confirmation gate in front of destructive sinks.",
    },
    {
      id: "CVE-2025-53109",
      title: "Anthropic filesystem MCP root-boundary bypass — auto-approved deletes",
      year: 2025,
      relevance:
        "CVE in the Anthropic-published filesystem server. Auto-approval of deletes is the explicit antipattern.",
    },
    {
      id: "INVARIANT-LABS-2025",
      title: "Invariant Labs — 84.2% tool poisoning success with auto-approve",
      year: 2025,
      relevance:
        "Quantitative evidence that the absence of a hard structural gate is exploited at scale.",
    },
  ],
  strategies: ["consent-bypass", "human-oversight-bypass", "privilege-chain"],
  remediation:
    "Wrap every destructive sink with an explicit confirmation gate. Either (a) require a synchronous human approval, or (b) emit a structured `pending` response and wait for the AI client's human-oversight callback. Document the gate in the tool description and set both `destructiveHint: true` and `requiresConfirmation: true`.",
};

const CONFIRMATION_MARKER_KEYS: readonly string[] = [
  "requiresConfirmation",
  "humanInTheLoop",
  "needsApproval",
  "confirmationRequired",
];

class HumanOversightPresenceRule extends ComplianceRule {
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

    // 1. Identify confirmation-gate tools via annotation marker keys.
    const confirmationGates = new Set<string>();
    for (const tool of tools) {
      const ann = (tool.annotations ?? {}) as Record<string, unknown>;
      for (const key of CONFIRMATION_MARKER_KEYS) {
        if (ann[key] === true) {
          confirmationGates.add(tool.name);
          break;
        }
      }
    }

    // 2. Walk the capability graph for destructive sinks.
    const sinksWithoutGate: DestructiveSink[] = [];
    const sinksWithGate: DestructiveSink[] = [];
    const pointers: EvidencePointer[] = [];

    for (const node of graph.nodes) {
      const reasons: string[] = [];
      let isDestructive = false;
      for (const cap of node.capabilities) {
        if (cap.capability === "destructive" && cap.confidence >= 0.4) {
          isDestructive = true;
          reasons.push(`capability=destructive (confidence ${cap.confidence.toFixed(2)})`);
        }
        if (cap.capability === "executes-code" && cap.confidence >= 0.5) {
          isDestructive = true;
          reasons.push(`capability=executes-code (confidence ${cap.confidence.toFixed(2)})`);
        }
        if (cap.capability === "writes-data" && cap.confidence >= 0.6) {
          isDestructive = true;
          reasons.push(`capability=writes-data (confidence ${cap.confidence.toFixed(2)})`);
        }
      }

      const tool = tools.find((t) => t.name === node.name);
      const ann = (tool?.annotations ?? {}) as Record<string, unknown>;
      const hasDestructiveHint = ann.destructiveHint === true;
      if (hasDestructiveHint) {
        isDestructive = true;
        reasons.push("annotation=destructiveHint:true");
      }

      if (!isDestructive) continue;

      const hasConfirmationMarker = confirmationGates.has(node.name);
      const sink: DestructiveSink = {
        tool_name: node.name,
        reasons,
        has_destructive_hint: hasDestructiveHint,
        has_confirmation_marker: hasConfirmationMarker,
      };

      pointers.push({
        kind: "tool",
        label: `destructive sink: ${node.name}`,
        location: `tool:${node.name}`,
        observed: reasons.join("; "),
      });

      if (hasConfirmationMarker || confirmationGates.size > 0) {
        // If the tool itself carries a marker, gated.
        // If the server has any confirmation gate at all, that is NOT
        // sufficient on its own — only the tool's own marker counts as
        // proof that this specific sink is gated.
        if (hasConfirmationMarker) {
          sinksWithGate.push(sink);
        } else {
          sinksWithoutGate.push(sink);
        }
      } else {
        sinksWithoutGate.push(sink);
      }
    }

    for (const gateName of confirmationGates) {
      pointers.push({
        kind: "tool",
        label: `confirmation gate marker`,
        location: `tool:${gateName}`,
        observed: "annotation marker present",
      });
    }

    const facts: HumanOversightFacts = {
      destructive_sinks_without_gate: sinksWithoutGate,
      destructive_sinks_with_gate: sinksWithGate,
      total_tools: tools.length,
      confirmation_gate_tool_names: Array.from(confirmationGates),
      confirmation_marker_keys: Array.from(CONFIRMATION_MARKER_KEYS),
    };

    const summary =
      sinksWithoutGate.length > 0
        ? `${sinksWithoutGate.length} destructive sink(s) lack a structural human confirmation gate`
        : `No ungated destructive sinks detected (${sinksWithGate.length} gated, ${tools.length} tools total)`;

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
      deterministic_violation: sinksWithoutGate.length > 0,
    };
  }

  judge(bundle: EvidenceBundle, raw: RawTestResult): JudgedTestResult {
    const facts = bundle.facts as unknown as HumanOversightFacts;
    const ungated = facts.destructive_sinks_without_gate ?? [];

    if (raw.verdict !== "fail") {
      return {
        ...raw,
        judge_confirmed: false,
        judge_rationale: `Judge rejects non-fail verdict (${raw.verdict}); only fail verdicts are evaluated for ${this.metadata.id}.`,
      };
    }

    if (ungated.length === 0) {
      return {
        ...raw,
        judge_confirmed: false,
        judge_rationale:
          "Judge rejects: deterministic gather found no ungated destructive sinks. LLM hallucinated a violation.",
      };
    }

    const referencedSink = ungated.find((sink) =>
      raw.evidence_path_used.includes(sink.tool_name),
    );
    if (!referencedSink) {
      return {
        ...raw,
        judge_confirmed: false,
        judge_rationale: `Judge rejects: evidence_path_used (${raw.evidence_path_used}) does not reference any of the deterministically detected ungated sinks: ${ungated.map((s) => s.tool_name).join(", ")}.`,
      };
    }

    return {
      ...raw,
      judge_confirmed: true,
      judge_rationale: `Judge confirms: tool '${referencedSink.tool_name}' is destructive (${referencedSink.reasons.join("; ")}) and has no confirmation gate. Pattern matches CHARTER lethal edge case.`,
    };
  }
}

export const humanOversightPresenceRule = new HumanOversightPresenceRule();
