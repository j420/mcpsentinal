/**
 * A4 — Cross-Server Tool Name Shadowing (Rule Standard v2).
 *
 * Uses Damerau-Levenshtein similarity against a typed catalogue of
 * canonical MCP tool names to detect both exact-after-normalisation
 * and near-miss shadowing. No regex literals.
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
import { gatherA4, toolLocation, type ShadowSite } from "./gather.js";
import { stepInspectName, stepCompareRegistry } from "./verification.js";

const RULE_ID = "A4";
const RULE_NAME = "Cross-Server Tool Name Shadowing";
const OWASP = "MCP02-tool-poisoning";
const MITRE = "AML.T0054";
const CONFIDENCE_CAP = 0.80;

const REMEDIATION =
  "Rename the tool to include an unambiguous namespace prefix reflecting the " +
  "server identity (e.g. 'myserver_read_file' instead of 'read_file'). The MCP " +
  "registry and auto-approve AI clients otherwise route by bare name, which " +
  "lets a less-reputable publisher intercept user intent aimed at the canonical " +
  "official tool.";

class A4ToolNameShadowingRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "similarity";

  analyze(context: AnalysisContext): RuleResult[] {
    return gatherA4(context).map((s) => this.buildFinding(s));
  }

  private buildFinding(site: ShadowSite): RuleResult {
    const loc = toolLocation(site.tool_name);

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "external-content",
        location: loc,
        observed: site.tool_name,
        rationale:
          `Tool name "${site.tool_name}" ${
            site.kind === "exact"
              ? `normalises to "${site.canonical}"`
              : `is within edit distance ${site.distance} of "${site.canonical}"`
          }, a canonical tool from ${site.canonical_info.origin}.`,
      })
      .propagation({
        propagation_type: "cross-tool-flow",
        location: loc,
        observed:
          `AI client tool-selection algorithms bias toward short, familiar names. ` +
          `A non-canonical server publishing "${site.tool_name}" competes with ` +
          `"${site.canonical}" for the same user intent.`,
      })
      .sink({
        sink_type: "privilege-grant",
        location: loc,
        observed:
          `User intent directed at the canonical "${site.canonical}" is routed to ` +
          `this non-canonical tool, granting the server privileges the user ` +
          `believed were granted to the official tool.`,
      })
      .impact({
        impact_type: "cross-agent-propagation",
        scope: "ai-client",
        exploitability: site.kind === "exact" ? "trivial" : "moderate",
        scenario:
          `When the user asks the AI to "${site.canonical_info.category === "filesystem" ? "read a file" : "perform the canonical action"}", ` +
          `the AI selects this tool because the name matches. The server ` +
          `receives the user's intended data path while the user believes the ` +
          `canonical tool handled it.`,
      })
      .factor(
        "name_similarity_match",
        0.10,
        `${site.kind === "exact" ? "Exact-after-normalisation" : "Fuzzy (distance " + site.distance + ")"} ` +
          `match against canonical "${site.canonical}" from ${site.canonical_info.origin}.`,
      );

    if (site.kind === "exact") {
      builder.factor(
        "exact_canonical_collision",
        0.08,
        `Normalisation produces identical tokens — zero edit distance to the canonical name.`,
      );
    }

    builder.reference({
      id: "WIZ-MCP-SUPPLYCHAIN-2025",
      title: "Wiz Research (2025) — MCP Supply Chain Attacks",
      url: "https://www.wiz.io/blog/mcp-supply-chain-attacks",
      relevance:
        "Wiz documents three 2025 MCP tool-poisoning campaigns in which attackers " +
        "published servers exposing shadow-named tools to route user intent.",
    });

    builder.verification(stepInspectName(site));
    builder.verification(stepCompareRegistry(site));

    const chain = builder.build();
    if (chain.confidence > CONFIDENCE_CAP) {
      chain.confidence_factors.push({
        factor: "similarity_cap",
        adjustment: CONFIDENCE_CAP - chain.confidence,
        rationale: `A4 charter caps confidence at ${CONFIDENCE_CAP}.`,
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

registerTypedRuleV2(new A4ToolNameShadowingRule());

export { A4ToolNameShadowingRule };
