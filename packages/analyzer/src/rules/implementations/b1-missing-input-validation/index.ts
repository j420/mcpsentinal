/**
 * B1 — Missing Input Validation (Rule Standard v2).
 * Structural walk of every tool's input_schema for unconstrained params.
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder } from "../../../evidence.js";
import { gatherB1, toolLocation, type UnconstrainedSite } from "./gather.js";
import { stepInspectSchema, stepAddConstraint } from "./verification.js";

const RULE_ID = "B1";
const RULE_NAME = "Missing Input Validation";
const OWASP = "MCP07-insecure-config";
const CONFIDENCE_CAP = 0.85;

const REMEDIATION =
  "Add at least one validation keyword to every string and number parameter. " +
  "For strings: maxLength, pattern, format, or enum. For numbers: minimum, " +
  "maximum, or multipleOf. JSON Schema validation runs before the tool handler " +
  "and is the cheapest first-line defence against injection and DoS.";

class B1MissingInputValidationRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    return gatherB1(context).map((s) => this.buildFinding(s));
  }

  private buildFinding(site: UnconstrainedSite): RuleResult {
    const loc = toolLocation(site.tool_name);

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "user-parameter",
        location: loc,
        observed: `${site.unconstrained.length}/${site.total_params} parameters unconstrained.`,
        rationale:
          `Tool "${site.tool_name}" accepts parameters without structural validation. ` +
          `The AI fills each parameter from user input; nothing in the schema rejects ` +
          `injection payloads, oversized strings, or out-of-range numbers before they ` +
          `reach the tool handler.`,
      })
      .propagation({
        propagation_type: "schema-unconstrained",
        location: loc,
        observed:
          `Unconstrained parameters: ${site.unconstrained.map((u) => `${u.param}(${u.type})`).join(", ")}.`,
      })
      .sink({
        sink_type: "code-evaluation",
        location: loc,
        observed:
          `Tool handler receives raw parameter values with no upfront validation.`,
      })
      .impact({
        impact_type: "config-poisoning",
        scope: "server-host",
        exploitability: "moderate",
        scenario:
          `Injection payloads (shell metacharacters, path traversal sequences, ` +
          `SQL-like strings) and abuse payloads (oversized or out-of-range values) ` +
          `pass validation unimpeded and reach the handler, where any parser bug ` +
          `becomes exploitable.`,
      })
      .factor(
        "unconstrained_parameters",
        0.05 + Math.min(0.1, site.unconstrained.length * 0.02),
        `${site.unconstrained.length} parameter(s) lack validation constraints.`,
      );

    builder.reference({
      id: "OWASP-MCP07",
      title: "OWASP MCP Top 10 — MCP07 Insecure Configuration",
      url: "https://owasp.org/www-project-mcp-top-10/",
      relevance:
        "Missing schema constraints are the canonical insecure-configuration " +
        "precursor to downstream injection.",
    });

    builder.verification(stepInspectSchema(site));
    builder.verification(stepAddConstraint(site));

    const chain = builder.build();
    if (chain.confidence > CONFIDENCE_CAP) {
      chain.confidence_factors.push({
        factor: "structural_cap",
        adjustment: CONFIDENCE_CAP - chain.confidence,
        rationale: `B1 charter caps confidence at ${CONFIDENCE_CAP}.`,
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

registerTypedRuleV2(new B1MissingInputValidationRule());

export { B1MissingInputValidationRule };
