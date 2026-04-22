/**
 * A2 — Excessive Scope Claims in Tool Description (Rule Standard v2).
 *
 * Detects modifier+noun co-occurrence patterns that advertise sweeping
 * privilege scope in a tool description. Linguistic detection via
 * typed claim catalogue; no regex literals.
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
import { gatherA2, toolLocation, type ClaimSite } from "./gather.js";
import { stepInspectClaim, stepInspectSchema } from "./verification.js";

const RULE_ID = "A2";
const RULE_NAME = "Excessive Scope Claims in Description";
const OWASP = "MCP06-excessive-permissions";
const MITRE: string | null = null;
const CONFIDENCE_CAP = 0.80;

const REMEDIATION =
  "Rewrite the description so it accurately reflects the tool's scope. Replace " +
  "sweeping claims (\"full access\", \"unrestricted\", \"admin mode\") with the " +
  "specific operations the tool actually performs and the specific subset of " +
  "resources it touches. The AI client uses the description as its mental model " +
  "of acceptable privilege — overclaims directly undermine least-privilege review.";

class A2ExcessiveScopeClaimsRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "linguistic";

  analyze(context: AnalysisContext): RuleResult[] {
    const sites = gatherA2(context);
    if (sites.length === 0) return [];
    // Group by tool so each tool gets ONE finding even if multiple claim patterns match.
    const byTool = new Map<string, ClaimSite[]>();
    for (const s of sites) {
      const arr = byTool.get(s.tool_name) ?? [];
      arr.push(s);
      byTool.set(s.tool_name, arr);
    }
    const out: RuleResult[] = [];
    for (const [tool_name, tool_sites] of byTool.entries()) {
      out.push(this.buildFinding(tool_name, tool_sites));
    }
    return out;
  }

  private buildFinding(tool_name: string, sites: ClaimSite[]): RuleResult {
    const primary = sites.reduce((b, s) => (s.weight > b.weight ? s : b), sites[0]);
    const loc = toolLocation(tool_name);

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "external-content",
        location: loc,
        observed: primary.observed,
        rationale:
          `Tool description for "${tool_name}" advertises excessive scope via ` +
          `${sites.length} claim pattern(s). Strongest: "${primary.label}". AI ` +
          `clients use the description to shape permission-approval decisions; ` +
          `broad claims drive auto-approval.`,
      })
      .propagation({
        propagation_type: "description-directive",
        location: loc,
        observed:
          `The scope claim flows from tool metadata into the AI's permission ` +
          `reasoning. No MCP client strips superlative language before ingestion.`,
      })
      .sink({
        sink_type: "privilege-grant",
        location: loc,
        observed:
          `AI grants tool "${tool_name}" the broad scope advertised in the description.`,
      })
      .impact({
        impact_type: "privilege-escalation",
        scope: "server-host",
        exploitability: "moderate",
        scenario:
          `When an operation touches a sensitive resource, the AI references the ` +
          `description's scope claim rather than the minimum necessary scope. The ` +
          `tool gains de-facto privilege beyond least-privilege boundaries.`,
      })
      .factor(
        "description_scope_claim",
        0.10,
        `Found ${sites.length} scope-claim pattern(s); primary weight ${primary.weight.toFixed(2)}.`,
      );

    if (sites.length >= 2) {
      builder.factor(
        "multiple_scope_signals",
        0.05,
        `${sites.length} distinct claim patterns co-occur in the same description.`,
      );
    }

    if (primary.schema_has_constraints) {
      builder.factor(
        "schema_contradicts_claim",
        -0.05,
        `Schema has structured constraints that narrow the actual runtime scope — ` +
          `the claim is overstated rather than enacted.`,
      );
    }

    builder.reference({
      id: "OWASP-MCP06",
      title: "OWASP MCP Top 10 — MCP06 Excessive Permissions",
      url: "https://owasp.org/www-project-mcp-top-10/",
      relevance:
        "A tool description that advertises excessive scope is the canonical " +
        "linguistic instance of MCP06. The claim shapes AI consent decisions " +
        "even when the implementation is more restrained.",
    });

    builder.verification(stepInspectClaim(primary));
    builder.verification(stepInspectSchema(tool_name, primary.schema_has_constraints));

    const chain = builder.build();
    if (chain.confidence > CONFIDENCE_CAP) {
      chain.confidence_factors.push({
        factor: "linguistic_scoring_cap",
        adjustment: CONFIDENCE_CAP - chain.confidence,
        rationale: `A2 charter caps confidence at ${CONFIDENCE_CAP}.`,
      });
      chain.confidence = CONFIDENCE_CAP;
    }

    return {
      rule_id: RULE_ID,
      severity: "high",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain,
    };
  }
}

registerTypedRuleV2(new A2ExcessiveScopeClaimsRule());

export { A2ExcessiveScopeClaimsRule };
