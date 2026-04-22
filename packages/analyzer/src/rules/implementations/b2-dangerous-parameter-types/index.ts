/**
 * B2 — Dangerous Parameter Types (Rule Standard v2).
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
import { gatherB2, toolLocation, type DangerousSite } from "./gather.js";
import { stepInspectParams, stepInspectHandler } from "./verification.js";

const RULE_ID = "B2";
const RULE_NAME = "Dangerous Parameter Types";
const OWASP = "MCP03-command-injection";
const CONFIDENCE_CAP = 0.85;

const REMEDIATION =
  "Replace dangerous parameter names with semantic, narrow equivalents — " +
  "\"command\" → \"operation\" with an enum of allowed verbs; \"sql\" → a " +
  "structured filter object; \"path\" → a constrained \"relative_path\" with " +
  "pattern and maxLength. Add pattern / enum constraints to every remaining " +
  "dangerous parameter so the schema itself rejects injection payloads.";

class B2DangerousParameterTypesRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    return gatherB2(context).map((s) => this.buildFinding(s));
  }

  private buildFinding(site: DangerousSite): RuleResult {
    const loc = toolLocation(site.tool_name);
    const primary = site.params[0];

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "user-parameter",
        location: loc,
        observed: site.params.map((p) => p.name).join(", "),
        rationale:
          `Tool "${site.tool_name}" declares ${site.params.length} parameter(s) ` +
          `whose names advertise direct paths to dangerous sinks. AI clients ` +
          `use parameter names as part of tool-selection reasoning, so the ` +
          `name itself biases the AI toward filling the parameter with ` +
          `sink-appropriate (and therefore dangerous) content.`,
      })
      .propagation({
        propagation_type: "direct-pass",
        location: loc,
        observed: site.params.map((p) => `${p.name} → ${p.sink}`).join(", "),
      })
      .sink({
        sink_type: primary.sink,
        location: loc,
        observed: `Parameter "${primary.name}" (${primary.rationale}).`,
      })
      .impact({
        impact_type: "remote-code-execution",
        scope: "server-host",
        exploitability: "moderate",
        scenario:
          `If the handler passes any of [${site.params.map((p) => p.name).join(", ")}] ` +
          `to its downstream sink without validation, the parameter becomes an ` +
          `injection primitive. The schema-level name already signals the risk.`,
      })
      .factor(
        "dangerous_param_name",
        0.05 + Math.min(0.1, site.params.length * 0.03),
        `${site.params.length} parameter(s) with dangerous names.`,
      );

    builder.reference({
      id: "OWASP-MCP03",
      title: "OWASP MCP Top 10 — MCP03 Command Injection",
      url: "https://owasp.org/www-project-mcp-top-10/",
      relevance:
        "Dangerous parameter names advertise direct paths to execution / query / " +
        "eval sinks.",
    });

    builder.verification(stepInspectParams(site));
    builder.verification(stepInspectHandler(site));

    const chain = builder.build();
    if (chain.confidence > CONFIDENCE_CAP) {
      chain.confidence_factors.push({
        factor: "structural_cap",
        adjustment: CONFIDENCE_CAP - chain.confidence,
        rationale: `B2 charter caps confidence at ${CONFIDENCE_CAP}.`,
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

registerTypedRuleV2(new B2DangerousParameterTypesRule());

export { B2DangerousParameterTypesRule };
