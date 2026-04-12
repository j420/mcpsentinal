/**
 * Rule: destructive-operation-gating
 *
 * Detects destructive-capability tools that carry neither
 * destructiveHint=true nor any consent marker annotation. Pure
 * structural check over the capability graph and tool annotations.
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

interface UngatedTool {
  tool_name: string;
  capabilities: string[];
  destructive_hint_value: unknown;
  read_only_hint_value: unknown;
  consent_marker_keys: string[];
}

interface GatingFacts {
  ungated_destructive_tools: UngatedTool[];
  correctly_gated_tools: string[];
  lying_read_only_tools: UngatedTool[];
}

const METADATA: ComplianceRuleMetadata = {
  id: "shared-destructive-operation-gating",
  name: "Destructive Operation Gating",
  severity: "critical",
  intent:
    "Every destructive, code-executing, or irreversible tool MUST carry destructiveHint=true and a consent annotation so clients can gate it behind explicit user confirmation.",
  applies_to: [
    { framework: "owasp_mcp", category: "MCP06 — Excessive Permissions", control: "MCP06" },
    { framework: "owasp_asi", category: "ASI09 — Human Oversight", control: "ASI09" },
    { framework: "cosai", category: "T2 — Human-in-the-Loop", control: "T2" },
    { framework: "cosai", category: "T9 — Tool Abuse", control: "T9" },
    { framework: "maestro", category: "L6 — Security/Safety", control: "L6" },
    { framework: "eu_ai_act", category: "Article 14 — Human Oversight", control: "Art.14" },
    { framework: "mitre_atlas", category: "AML.T0059 — Memory Manipulation", control: "AML.T0059" },
  ],
  threat_refs: [
    {
      id: "CVE-2025-53109",
      title: "Anthropic filesystem server root bypass",
      year: 2025,
      relevance: "Destructive operations executed outside intended scope with no user confirmation.",
    },
    {
      id: "CVE-2025-53110",
      title: "Anthropic filesystem server boundary bypass variant",
      year: 2025,
      relevance: "Second variant of the boundary bypass that enabled destructive writes.",
    },
    {
      id: "OWASP-ASI09",
      title: "OWASP Agentic Top 10 — Human Oversight",
      relevance: "Names the failure class this rule structurally prevents.",
    },
    {
      id: "EU-AI-Act-Art14",
      title: "EU AI Act Article 14 — Human Oversight",
      relevance: "Regulatory baseline requiring effective human oversight of high-risk decisions.",
    },
    {
      id: "Invariant-2025-DESTRUCT",
      title: "Destructive tool without consent gating",
      year: 2025,
      relevance: "Documented production incident caused by an ungated destructive tool.",
    },
  ],
  strategies: ["human-oversight-bypass", "consent-bypass", "privilege-chain"],
  remediation:
    "Add destructiveHint=true and a consent annotation (requiresConfirmation=true or humanInTheLoop=true) to every destructive, code-executing, or irreversible tool. Never ship a destructive tool with readOnlyHint=true.",
};

function isDestructiveNode(capabilityNames: string[]): boolean {
  return (
    capabilityNames.includes("destructive") ||
    capabilityNames.includes("executes-code") ||
    capabilityNames.includes("writes-data")
  );
}

class DestructiveOperationGatingRule extends ComplianceRule {
  readonly metadata = METADATA;

  gatherEvidence(context: AnalysisContext): EvidenceBundle {
    const graph = graphFor(context);

    const ungated: UngatedTool[] = [];
    const gated: string[] = [];
    const lying: UngatedTool[] = [];

    for (const node of graph.nodes) {
      const caps = node.capabilities.map((c) => c.capability);
      if (!isDestructiveNode(caps)) continue;

      const annotations =
        ((context.tools ?? []).find((t) => t.name === node.name)?.annotations ??
          {}) as Record<string, unknown>;
      const destructiveHint = annotations["destructiveHint"];
      const readOnlyHint = annotations["readOnlyHint"];
      const consentKeys: string[] = [];
      for (const key of CONSENT_MARKER_KEYS) {
        if (typeof annotations[key] !== "undefined") consentKeys.push(key);
      }

      const info: UngatedTool = {
        tool_name: node.name,
        capabilities: caps,
        destructive_hint_value: destructiveHint,
        read_only_hint_value: readOnlyHint,
        consent_marker_keys: consentKeys,
      };

      // Lying: destructive capability but claims read-only.
      if (readOnlyHint === true) {
        lying.push(info);
        ungated.push(info);
        continue;
      }

      // Correctly gated: destructiveHint=true AND at least one consent marker.
      if (destructiveHint === true && consentKeys.length > 0) {
        gated.push(node.name);
        continue;
      }

      ungated.push(info);
    }

    const pointers: EvidencePointer[] = [];
    for (const tool of ungated) {
      pointers.push({
        kind: "tool",
        label: "destructive tool without explicit gating",
        location: `tool:${tool.tool_name}`,
        observed: `caps=${tool.capabilities.join("+")}; destructiveHint=${String(tool.destructive_hint_value)}; readOnlyHint=${String(tool.read_only_hint_value)}`,
      });
    }

    const facts: GatingFacts = {
      ungated_destructive_tools: ungated,
      correctly_gated_tools: gated,
      lying_read_only_tools: lying,
    };

    return makeBundle({
      rule_id: this.metadata.id,
      context,
      summary:
        ungated.length > 0
          ? `${ungated.length} destructive tool(s) without consent gating${lying.length > 0 ? ` (${lying.length} falsely claim readOnly)` : ""}`
          : `All ${gated.length} destructive tool(s) correctly gated`,
      facts: facts as unknown as Record<string, unknown>,
      pointers,
      deterministic_violation: ungated.length > 0,
    });
  }

  judge(bundle: EvidenceBundle, raw: RawTestResult): JudgedTestResult {
    const facts = bundle.facts as unknown as GatingFacts;
    const result = standardJudge({
      raw,
      deterministic: facts.ungated_destructive_tools ?? [],
      ruleId: this.metadata.id,
    });
    return {
      ...raw,
      judge_confirmed: result.confirmed,
      judge_rationale: result.rationale,
    };
  }
}

export const destructiveOperationGatingRule =
  new DestructiveOperationGatingRule();
