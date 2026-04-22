/** B7 — Dangerous Default Parameter Values (Rule Standard v2). */

import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder } from "../../../evidence.js";
import { gatherB7, paramLocation, type B7Site } from "./gather.js";
import { stepInspectDefault, stepFlipSafeDefault } from "./verification.js";

const RULE_ID = "B7";
const RULE_NAME = "Dangerous Default Parameter Values";
const OWASP = "MCP06-excessive-permissions";
const CONFIDENCE_CAP = 0.90;

const REMEDIATION =
  "Flip every dangerous default to its safe equivalent. Destructive booleans " +
  "(overwrite, recursive, force, disable_ssl_verify, delete, skip_validation) " +
  "must default to false. read_only must default to true. Path / glob parameters " +
  "must default to a narrow, explicit value — never '/', '*', or '**'. Callers " +
  "that want the dangerous behaviour must opt in explicitly.";

class B7DangerousDefaultsRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    return gatherB7(context).map((s) => this.buildFinding(s));
  }

  private buildFinding(site: B7Site): RuleResult {
    const loc = paramLocation(site.tool_name, site.parameter_name);

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "user-parameter",
        location: loc,
        observed: `default: "${site.default_value}"`,
        rationale:
          `Parameter "${site.parameter_name}" of tool "${site.tool_name}" defaults to ` +
          `"${site.default_value}" — ${site.rationale}. Callers that omit the ` +
          `parameter inherit the dangerous behaviour without ever making an ` +
          `explicit choice.`,
      })
      .propagation({
        propagation_type: "direct-pass",
        location: loc,
        observed:
          `Default value flows directly to the handler when the AI or user omits ` +
          `the parameter.`,
      })
      .sink({
        sink_type:
          site.category === "path-root-default" || site.category === "wildcard-default"
            ? "file-write"
            : "privilege-grant",
        location: loc,
        observed:
          `Handler receives ${site.label} by default — the least-privilege ` +
          `principle is silently inverted.`,
      })
      .impact({
        impact_type: "privilege-escalation",
        scope: "server-host",
        exploitability: "trivial",
        scenario:
          `Any caller (AI or human) that omits "${site.parameter_name}" triggers the ` +
          `dangerous behaviour without review or confirmation. CyberArk FSP research ` +
          `documents LLMs are biased toward inheriting defaults during tool-call ` +
          `argument synthesis.`,
      })
      .factor(
        "dangerous_default_value",
        0.15,
        `Parameter "${site.parameter_name}" default "${site.default_value}" matches ` +
          `${site.category} catalogue.`,
      );

    builder.reference({
      id: "OWASP-MCP06",
      title: "OWASP MCP Top 10 — MCP06 Excessive Permissions",
      url: "https://owasp.org/www-project-mcp-top-10/",
      relevance:
        "Dangerous defaults violate least-privilege by inverting the safe default.",
    });

    builder.verification(stepInspectDefault(site));
    builder.verification(stepFlipSafeDefault(site));

    const chain = builder.build();
    if (chain.confidence > CONFIDENCE_CAP) {
      chain.confidence_factors.push({
        factor: "structural_cap",
        adjustment: CONFIDENCE_CAP - chain.confidence,
        rationale: `B7 charter caps confidence at ${CONFIDENCE_CAP}.`,
      });
      chain.confidence = CONFIDENCE_CAP;
    }

    return {
      rule_id: RULE_ID,
      severity: "high",
      owasp_category: OWASP,
      mitre_technique: null,
      remediation: REMEDIATION,
      chain,
    };
  }
}

registerTypedRuleV2(new B7DangerousDefaultsRule());

export { B7DangerousDefaultsRule };
