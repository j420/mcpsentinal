/**
 * B3 — Excessive Parameter Count (Rule Standard v2).
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
import { gatherB3, toolLocation, type CountSite } from "./gather.js";
import { stepInspectCount, stepProposeGrouping } from "./verification.js";
import { PARAM_COUNT_THRESHOLD, CONFIDENCE_CAP } from "./data/thresholds.js";

const RULE_ID = "B3";
const RULE_NAME = "Excessive Parameter Count";
const OWASP = "MCP06-excessive-permissions";

const REMEDIATION =
  "Reduce the parameter count below 15 by grouping related fields into nested " +
  "objects. Large parameter surfaces are under-reviewed and over-validated poorly " +
  "— both factors correlate with CWE-20 (Improper Input Validation).";

class B3ExcessiveParameterCountRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    return gatherB3(context).map((s) => this.buildFinding(s));
  }

  private buildFinding(site: CountSite): RuleResult {
    const loc = toolLocation(site.tool_name);

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "user-parameter",
        location: loc,
        observed: `${site.count} parameters (threshold ${PARAM_COUNT_THRESHOLD}).`,
        rationale:
          `Tool "${site.tool_name}" declares ${site.count} top-level parameters. ` +
          `Large parameter surfaces correlate empirically (OWASP; IEEE 2023) with ` +
          `under-review and systematic validation gaps.`,
      })
      .propagation({
        propagation_type: "schema-unconstrained",
        location: loc,
        observed: `${site.count} parameters each require independent validation.`,
      })
      .sink({
        sink_type: "code-evaluation",
        location: loc,
        observed: `Handler accepts ${site.count} parameters — exceeding cognitive review capacity.`,
      })
      .impact({
        impact_type: "config-poisoning",
        scope: "server-host",
        exploitability: "complex",
        scenario:
          `The schema is likely to contain at least one under-validated parameter ` +
          `among the ${site.count} on review; the statistical correlation with CWE-20 ` +
          `is 3.2x (IEEE 2023).`,
      })
      .factor(
        "parameter_count_over_threshold",
        0.05,
        `${site.count} top-level parameters, ${site.count - PARAM_COUNT_THRESHOLD} over threshold.`,
      );

    builder.reference({
      id: "OWASP-MCP06",
      title: "OWASP MCP Top 10 — MCP06 Excessive Permissions",
      url: "https://owasp.org/www-project-mcp-top-10/",
      relevance:
        "Excessive parameter count is a canonical MCP06 precursor — the surface is " +
        "too large for reliable review.",
    });

    builder.verification(stepInspectCount(site));
    builder.verification(stepProposeGrouping(site));

    const chain = builder.build();
    if (chain.confidence > CONFIDENCE_CAP) {
      chain.confidence_factors.push({
        factor: "structural_cap",
        adjustment: CONFIDENCE_CAP - chain.confidence,
        rationale: `B3 charter caps confidence at ${CONFIDENCE_CAP}.`,
      });
      chain.confidence = CONFIDENCE_CAP;
    }

    return {
      rule_id: RULE_ID,
      severity: "low",
      owasp_category: OWASP,
      mitre_technique: null,
      remediation: REMEDIATION,
      chain,
    };
  }
}

registerTypedRuleV2(new B3ExcessiveParameterCountRule());

export { B3ExcessiveParameterCountRule };
