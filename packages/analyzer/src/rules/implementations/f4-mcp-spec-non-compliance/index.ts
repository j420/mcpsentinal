/**
 * F4 — MCP Spec Non-Compliance (v2)
 *
 * Orchestrator. Consumes the per-tool spec-field violations gathered by
 * `gather.ts` and emits v2 RuleResult[] with evidence chains that
 * point at the specific tool and specific field class. No regex
 * literals — all data lives in `./data/spec-fields.ts`.
 *
 * Confidence cap: 0.75 per charter. Spec compliance is inherently
 * heuristic — the rule may emit a finding against a tool that intentionally
 * omits a field under a future capability-negotiation flow.
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder, type EvidenceChain } from "../../../evidence.js";
import { gatherF4, type F4Site } from "./gather.js";
import { stepInspectToolEntry, stepCompareAgainstSpec } from "./verification.js";

const RULE_ID = "F4";
const RULE_NAME = "MCP Spec Non-Compliance";
const OWASP = "MCP07-insecure-config" as const;
const MITRE: string | null = null;
const CONFIDENCE_CAP = 0.75;

const REMEDIATION =
  "Populate the missing or empty field on the flagged tool per the MCP " +
  "specification. For `name`: choose a stable, non-empty identifier that is " +
  "unique within the server. For `description`: write a short sentence the LLM " +
  "can use to decide when to call the tool and the user can read before " +
  "approving. For `inputSchema`: emit a JSON Schema object describing every " +
  "parameter (use `{\"type\":\"object\",\"properties\":{}}` for tools that take " +
  "no arguments). Re-enumerate tools/list after the change and confirm the " +
  "scanner no longer reports F4 for this tool.";

const REF_OWASP_MCP07 = {
  id: "OWASP-MCP07-Insecure-Config",
  title: "OWASP MCP Top 10 — MCP07 Insecure Configuration",
  url: "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
  relevance:
    "MCP07 lists spec-deviation among the insecure-configuration signals that " +
    "downstream clients cannot safely reason about. Missing required or " +
    "recommended fields materially weaken the client's ability to filter, " +
    "log, and approve tool invocations.",
} as const;

class McpSpecNonComplianceRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherF4(context);
    return gathered.sites.map((site) => this.buildFinding(site));
  }

  private buildFinding(site: F4Site): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "external-content",
        location: site.toolLocation,
        observed: describeObserved(site),
        rationale: site.fieldEntry.rationale,
      })
      .sink({
        sink_type: "config-modification",
        location: site.toolLocation,
        observed:
          `Spec-field violation (${site.fieldClass}): the tool is served to ` +
          `MCP clients with a ${site.fieldEntry.requirement} field ` +
          `missing or malformed, per spec ${site.fieldEntry.spec_revision}.`,
      })
      .impact({
        impact_type: "config-poisoning",
        scope: "ai-client",
        exploitability: "moderate",
        scenario: site.fieldEntry.impact_scenario,
      })
      .factor(
        "spec_field_class",
        0.05,
        `Classified as "${site.fieldClass}" against MCP spec ` +
          `${site.fieldEntry.spec_revision}. Requirement level: ` +
          `${site.fieldEntry.requirement}.`,
      )
      .factor(
        site.fieldEntry.requirement === "required"
          ? "required_field_missing"
          : "recommended_field_missing",
        site.fieldEntry.requirement === "required" ? 0.1 : 0.03,
        site.fieldEntry.requirement === "required"
          ? `The spec marks this field as REQUIRED; absence is a direct protocol violation.`
          : `The spec marks this field as RECOMMENDED; absence is a compliance gap ` +
            `rather than a protocol violation. The low severity reflects this nuance.`,
      )
      .reference(REF_OWASP_MCP07)
      .verification(stepInspectToolEntry(site))
      .verification(stepCompareAgainstSpec(site));

    const chain = capConfidence(builder.build(), CONFIDENCE_CAP);

    return {
      rule_id: RULE_ID,
      severity: "low",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain,
    };
  }
}

function describeObserved(site: F4Site): string {
  const display = site.rawToolName === "" ? "(empty)" : site.rawToolName;
  switch (site.fieldClass) {
    case "tool-name-empty":
      return `Tool served with empty or missing \`name\` (observed: "${display}")`;
    case "tool-name-whitespace":
      return `Tool served with whitespace-only \`name\` (observed: "${display}")`;
    case "tool-description-missing":
      return `Tool "${display}" served with missing or empty \`description\``;
    case "tool-input-schema-missing":
      return `Tool "${display}" served with missing \`inputSchema\``;
  }
}

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `F4 charter caps confidence at ${cap} — spec compliance is a heuristic ` +
      `signal. A future MCP revision may formalise capability negotiation for ` +
      `the omitted field, or the analyzer may not have seen the negotiated ` +
      `protocol version. The 0.25 gap signals "compliance gap detected, ` +
      `reviewer confirms against the live spec revision".`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new McpSpecNonComplianceRule());

// Export for tests (dynamic instantiation without relying on the global registry).
export { McpSpecNonComplianceRule };
