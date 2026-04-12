/**
 * Rule: capability-declaration-honesty
 *
 * Cross-checks context.declared_capabilities against the observed
 * tool/resource/prompt surface. Produces an EvidenceBundle that lists
 * undeclared uses and false declarations for per-framework reporting.
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
import { makeBundle, standardJudge } from "../../../rule-kit/index.js";

interface CapabilityMismatch {
  tool_name: string;
  capability: string;
  kind: "undeclared_use" | "false_declaration";
  observed: string;
}

interface HonestyFacts {
  undeclared_uses: CapabilityMismatch[];
  false_declarations: CapabilityMismatch[];
  all_mismatches: CapabilityMismatch[];
}

const METADATA: ComplianceRuleMetadata = {
  id: "shared-capability-declaration-honesty",
  name: "Capability Declaration Honesty",
  severity: "high",
  intent:
    "A server MUST keep its initialize-time capabilities declaration in sync with the observed runtime surface — no undeclared uses, no false declarations.",
  applies_to: [
    { framework: "owasp_mcp", category: "MCP07 — Insecure Configuration", control: "MCP07" },
    { framework: "owasp_asi", category: "ASI02 — Tool Misuse", control: "ASI02" },
    { framework: "cosai", category: "T7 — Protocol Misuse", control: "T7" },
    { framework: "maestro", category: "L4 — Deployment & Infrastructure", control: "L4" },
    { framework: "eu_ai_act", category: "Article 13 — Transparency", control: "Art.13" },
  ],
  threat_refs: [
    {
      id: "I12-MCP-Sentinel",
      title: "Analyzer rule I12 — Capability Escalation Post-Init",
      relevance: "Existing deterministic rule; this charter lifts it into the compliance-framework reporter.",
    },
    {
      id: "MCP-Spec-Init",
      title: "MCP initialize handshake capability contract",
      relevance: "Defines the declared capabilities object this rule enforces honesty against.",
    },
    {
      id: "OWASP-MCP07",
      title: "OWASP MCP Top 10 — Insecure Configuration",
      relevance: "Names the failure class this rule structurally prevents.",
    },
    {
      id: "Invariant-2025-CAPS",
      title: "Silent sampling capability",
      year: 2025,
      relevance: "Documented incident where a server triggered sampling callbacks without declaring the capability.",
    },
  ],
  strategies: ["trust-inversion", "privilege-chain", "shadow-state"],
  remediation:
    "Keep the initialize-time capabilities object in sync with actual server behavior. Remove declarations for unimplemented capabilities and declare any capability the server actually uses. Add a CI gate that runs this rule before publishing releases.",
};

class CapabilityDeclarationHonestyRule extends ComplianceRule {
  readonly metadata = METADATA;

  gatherEvidence(context: AnalysisContext): EvidenceBundle {
    const declared = context.declared_capabilities ?? null;
    const undeclaredUses: CapabilityMismatch[] = [];
    const falseDeclarations: CapabilityMismatch[] = [];

    const hasTools = (context.tools ?? []).length > 0;
    const hasResources = (context.resources ?? []).length > 0;
    const hasPrompts = (context.prompts ?? []).length > 0;

    // Undeclared-use checks: observed surface but declaration is false/absent.
    if (hasTools && declared?.tools !== true) {
      undeclaredUses.push({
        tool_name: "tools",
        capability: "tools",
        kind: "undeclared_use",
        observed: `${(context.tools ?? []).length} tools observed, not declared`,
      });
    }
    if (hasResources && declared?.resources !== true) {
      undeclaredUses.push({
        tool_name: "resources",
        capability: "resources",
        kind: "undeclared_use",
        observed: `${(context.resources ?? []).length} resources observed, not declared`,
      });
    }
    if (hasPrompts && declared?.prompts !== true) {
      undeclaredUses.push({
        tool_name: "prompts",
        capability: "prompts",
        kind: "undeclared_use",
        observed: `${(context.prompts ?? []).length} prompts observed, not declared`,
      });
    }

    // False-declaration checks: declared true but observed surface is empty.
    if (declared?.tools === true && !hasTools) {
      falseDeclarations.push({
        tool_name: "tools",
        capability: "tools",
        kind: "false_declaration",
        observed: "declared tools, none observed",
      });
    }
    if (declared?.resources === true && !hasResources) {
      falseDeclarations.push({
        tool_name: "resources",
        capability: "resources",
        kind: "false_declaration",
        observed: "declared resources, none observed",
      });
    }
    if (declared?.prompts === true && !hasPrompts) {
      falseDeclarations.push({
        tool_name: "prompts",
        capability: "prompts",
        kind: "false_declaration",
        observed: "declared prompts, none observed",
      });
    }

    const all = [...undeclaredUses, ...falseDeclarations];

    const pointers: EvidencePointer[] = all.map((m) => ({
      kind: "capability",
      label: m.kind === "undeclared_use" ? "capability used but not declared" : "capability declared but unused",
      location: `capability:${m.capability}`,
      observed: m.observed,
    }));

    const facts: HonestyFacts = {
      undeclared_uses: undeclaredUses,
      false_declarations: falseDeclarations,
      all_mismatches: all,
    };

    return makeBundle({
      rule_id: this.metadata.id,
      context,
      summary:
        all.length > 0
          ? `${undeclaredUses.length} undeclared use(s), ${falseDeclarations.length} false declaration(s)`
          : `Capability declaration honest across tools/resources/prompts`,
      facts: facts as unknown as Record<string, unknown>,
      pointers,
      deterministic_violation: undeclaredUses.length > 0,
    });
  }

  judge(bundle: EvidenceBundle, raw: RawTestResult): JudgedTestResult {
    const facts = bundle.facts as unknown as HonestyFacts;
    const result = standardJudge({
      raw,
      deterministic: facts.all_mismatches ?? [],
      ruleId: this.metadata.id,
    });
    return {
      ...raw,
      judge_confirmed: result.confirmed,
      judge_rationale: result.rationale,
    };
  }
}

export const capabilityDeclarationHonestyRule =
  new CapabilityDeclarationHonestyRule();
