/** B6 — Schema Allows Unconstrained Additional Properties (Rule Standard v2). */

import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder } from "../../../evidence.js";
import { gatherB6, toolLocation, type B6Site } from "./gather.js";
import { stepInspectAdditional, stepPinFalse } from "./verification.js";
import { CONFIDENCE_CAP } from "./data/config.js";

const RULE_ID = "B6";
const RULE_NAME = "Schema Allows Unconstrained Additional Properties";
const OWASP = "MCP07-insecure-config";

const REMEDIATION =
  "Set additionalProperties: false on every object schema. This rejects any key " +
  "outside the declared properties, closing the side-channel smuggling path and " +
  "enforcing the schema's stated contract.";

class B6UnconstrainedAdditionalRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    return gatherB6(context).map((s) => this.buildFinding(s));
  }

  private buildFinding(site: B6Site): RuleResult {
    const loc = toolLocation(site.tool_name);

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "user-parameter",
        location: loc,
        observed:
          site.variant === "explicit-true"
            ? "additionalProperties: true"
            : "additionalProperties: (unset, defaults to true)",
        rationale:
          `Tool "${site.tool_name}" input_schema accepts arbitrary extra keys. The ` +
          `declared properties are validated, but the handler may read undeclared ` +
          `keys that bypass every validation rule.`,
      })
      .propagation({
        propagation_type: "schema-unconstrained",
        location: loc,
        observed: "Undeclared keys pass through schema validation unchallenged.",
      })
      .sink({
        sink_type: "config-modification",
        location: loc,
        observed:
          "Handler receives a superset of declared parameters — each extra key is " +
          "an un-reviewed input.",
      })
      .impact({
        impact_type: "config-poisoning",
        scope: "server-host",
        exploitability: "moderate",
        scenario:
          "An attacker smuggles side-channel state (override flags, alternate paths) " +
          "through the additionalProperties loophole to a handler that may still " +
          "honour the key — per CyberArk FSP research.",
      })
      .factor("additional_properties_not_false", 0.05, `additionalProperties state: ${site.variant}.`);

    builder.reference({
      id: "CYBERARK-FSP-2025",
      title: "CyberArk Labs (2025) — Full Schema Poisoning",
      url: "https://www.cyberark.com/resources/threat-research-blog/full-schema-poisoning",
      relevance:
        "Additional-property smuggling is a documented FSP vector; pinning " +
        "additionalProperties: false closes it.",
    });

    builder.verification(stepInspectAdditional(site));
    builder.verification(stepPinFalse(site));

    const chain = builder.build();
    if (chain.confidence > CONFIDENCE_CAP) {
      chain.confidence_factors.push({
        factor: "structural_cap",
        adjustment: CONFIDENCE_CAP - chain.confidence,
        rationale: `B6 charter caps confidence at ${CONFIDENCE_CAP}.`,
      });
      chain.confidence = CONFIDENCE_CAP;
    }

    return {
      rule_id: RULE_ID,
      severity: "medium",
      owasp_category: OWASP,
      mitre_technique: null,
      remediation: REMEDIATION,
      chain,
    };
  }
}

registerTypedRuleV2(new B6UnconstrainedAdditionalRule());

export { B6UnconstrainedAdditionalRule };
