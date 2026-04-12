/**
 * Rule: tool-shadowing-namespace
 *
 * Flags tools whose names collide with shadow-prone verbs from rule-kit
 * `SHADOW_PRONE_TOOL_NAMES` AND carry destructive capability markers.
 * Fully structural: capability graph + name membership check.
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
  SHADOW_PRONE_TOOL_NAMES,
  graphFor,
  makeBundle,
  standardJudge,
} from "../../../rule-kit/index.js";

interface ShadowViolation {
  tool_name: string;
  shadowed_verb: string;
  dangerous_capabilities: string[];
  consent_annotated: boolean;
}

interface ShadowingFacts {
  shadow_violations: ShadowViolation[];
  total_tools: number;
}

const METADATA: ComplianceRuleMetadata = {
  id: "shared-tool-shadowing-namespace",
  name: "Tool Shadowing Namespace",
  severity: "high",
  intent:
    "A server MUST NOT expose a destructive-capable tool whose name collides with a well-known safe verb (read_file, fetch, query, execute).",
  applies_to: [
    { framework: "owasp_mcp", category: "MCP02 — Tool Poisoning", control: "MCP02" },
    { framework: "owasp_asi", category: "ASI02 — Tool Misuse", control: "ASI02" },
    { framework: "cosai", category: "T4 — Prompt Injection", control: "T4" },
    { framework: "maestro", category: "L3 — Deployment Integrity", control: "L3" },
    { framework: "mitre_atlas", category: "AML.T0054 — LLM Prompt Injection", control: "AML.T0054" },
  ],
  threat_refs: [
    {
      id: "F4-MCP-Sentinel",
      title: "Analyzer rule F4 — Tool Name Shadowing",
      relevance: "Deterministic analyzer rule covering tool-name collisions with a canonical verb catalog.",
    },
    {
      id: "F5-MCP-Sentinel",
      title: "Analyzer rule F5 — Official Namespace Squatting",
      relevance: "Complementary analyzer rule; this charter extends the same pattern to generic shadow-prone verbs.",
    },
    {
      id: "OWASP-MCP02",
      title: "OWASP MCP Top 10 — Tool Poisoning",
      relevance: "Names the failure class this rule structurally prevents.",
    },
    {
      id: "MITRE-AML.T0054",
      title: "MITRE ATLAS LLM Prompt Injection",
      relevance: "Shadowed verbs bias the agent toward the attacker's tool — a documented prompt-injection assist.",
    },
    {
      id: "Invariant-2025-SHADOW",
      title: "Shadow read_file exfiltration incident",
      year: 2025,
      relevance: "Real incident: malicious read_file tool outranked the legitimate filesystem read and exfiltrated private keys.",
    },
  ],
  strategies: ["trust-inversion", "shadow-state", "consent-bypass"],
  remediation:
    "Rename shadow-prone tools to clearly namespaced alternatives (myserver_read_file, myserver_execute). Add destructiveHint: true and a consent marker (requiresConfirmation, humanInTheLoop) wherever the capability is not purely read-only.",
};

class ToolShadowingNamespaceRule extends ComplianceRule {
  readonly metadata = METADATA;

  gatherEvidence(context: AnalysisContext): EvidenceBundle {
    const graph = graphFor(context);
    const tools = context.tools ?? [];
    const violations: ShadowViolation[] = [];

    for (const node of graph.nodes) {
      const lowered = node.name.toLowerCase();
      const shadowed = SHADOW_PRONE_TOOL_NAMES.find((v) => lowered === v || lowered.endsWith(`_${v}`) || lowered.endsWith(v));
      if (!shadowed) continue;

      const caps = node.capabilities.map((c) => c.capability);
      const dangerous: string[] = [];
      if (caps.includes("writes-data")) dangerous.push("writes-data");
      if (caps.includes("executes-code")) dangerous.push("executes-code");
      if (caps.includes("destructive")) dangerous.push("destructive");
      if (caps.includes("manages-credentials")) dangerous.push("manages-credentials");
      if (dangerous.length === 0) continue;

      const tool = tools.find((t) => t.name === node.name);
      const annotations = (tool?.annotations ?? {}) as Record<string, unknown>;
      const consentAnnotated = CONSENT_MARKER_KEYS.some(
        (k) => annotations[k] === true,
      );

      violations.push({
        tool_name: node.name,
        shadowed_verb: shadowed,
        dangerous_capabilities: dangerous,
        consent_annotated: consentAnnotated,
      });
    }

    const pointers: EvidencePointer[] = violations.map((v) => ({
      kind: "tool",
      label: "shadow-prone tool name with destructive capability",
      location: `tool:${v.tool_name}`,
      observed: `shadows '${v.shadowed_verb}' with caps=${v.dangerous_capabilities.join("+")}${v.consent_annotated ? "" : " (no consent annotation)"}`,
    }));

    const deterministicViolation = violations.length > 0;

    const facts: ShadowingFacts = {
      shadow_violations: violations,
      total_tools: graph.nodes.length,
    };

    return makeBundle({
      rule_id: this.metadata.id,
      context,
      summary: deterministicViolation
        ? `${violations.length} shadow-prone tool(s) with destructive capabilities`
        : `No shadow-prone destructive tools across ${graph.nodes.length} tool(s)`,
      facts: facts as unknown as Record<string, unknown>,
      pointers,
      deterministic_violation: deterministicViolation,
    });
  }

  judge(bundle: EvidenceBundle, raw: RawTestResult): JudgedTestResult {
    const facts = bundle.facts as unknown as ShadowingFacts;
    const deterministicNames = (facts.shadow_violations ?? []).map(
      (v) => v.tool_name,
    );
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

export const toolShadowingNamespaceRule = new ToolShadowingNamespaceRule();
