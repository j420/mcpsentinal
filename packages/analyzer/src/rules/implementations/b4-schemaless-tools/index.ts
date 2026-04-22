/** B4 — Schema-less Tools (Rule Standard v2). */

import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder } from "../../../evidence.js";
import { gatherB4, toolLocation, type SchemalessSite } from "./gather.js";
import { stepInspectAbsence, stepDefineSchema } from "./verification.js";
import { CONFIDENCE_CAP } from "./data/config.js";

const RULE_ID = "B4";
const RULE_NAME = "Schema-less Tools";
const OWASP = "MCP07-insecure-config";

const REMEDIATION =
  "Define a JSON Schema for the tool's input. Every production MCP tool must " +
  "declare the parameters the handler reads, with typed fields and at least one " +
  "structural constraint per field.";

class B4SchemalessToolsRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    return gatherB4(context).map((s) => this.buildFinding(s));
  }

  private buildFinding(site: SchemalessSite): RuleResult {
    const loc = toolLocation(site.tool_name);
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "user-parameter",
        location: loc,
        observed: "input_schema: null",
        rationale:
          `Tool "${site.tool_name}" exposes no input_schema. AI clients must ` +
          `synthesise parameter types and values from the ${site.description_length}-char ` +
          `description alone — no JSON Schema validation protects the handler.`,
      })
      .propagation({
        propagation_type: "schema-unconstrained",
        location: loc,
        observed: "No structural contract — the AI's parameter guess bypasses every schema defence.",
      })
      .sink({
        sink_type: "code-evaluation",
        location: loc,
        observed: "Handler receives whatever JSON the AI produced — no validation possible.",
      })
      .impact({
        impact_type: "config-poisoning",
        scope: "server-host",
        exploitability: "moderate",
        scenario:
          `Different MCP clients interpret schema absence differently (some reject, ` +
          `some accept arbitrary JSON); the tool's behaviour is unpredictable and ` +
          `under-tested against malicious input.`,
      })
      .factor("no_input_schema", 0.20, "Complete absence of schema is a strong misconfiguration signal.");

    builder.reference({
      id: "OWASP-MCP07",
      title: "OWASP MCP Top 10 — MCP07 Insecure Configuration",
      url: "https://owasp.org/www-project-mcp-top-10/",
      relevance: "Schema absence is the canonical MCP07 anti-pattern.",
    });

    builder.verification(stepInspectAbsence(site));
    builder.verification(stepDefineSchema(site));

    const chain = builder.build();
    if (chain.confidence > CONFIDENCE_CAP) {
      chain.confidence_factors.push({
        factor: "structural_cap",
        adjustment: CONFIDENCE_CAP - chain.confidence,
        rationale: `B4 charter caps confidence at ${CONFIDENCE_CAP}.`,
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

registerTypedRuleV2(new B4SchemalessToolsRule());

export { B4SchemalessToolsRule };
