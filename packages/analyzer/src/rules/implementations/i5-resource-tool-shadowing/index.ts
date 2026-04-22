/**
 * I5 — Resource-Tool Shadowing (Rule Standard v2).
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
import type { Location } from "../../location.js";
import { gatherI5, type I5Fact } from "./gather.js";
import { I5_CONFIDENCE_CAP } from "./data/config.js";
import { stepInspectResource, stepInspectTool } from "./verification.js";

const RULE_ID = "I5";
const RULE_NAME = "Resource-Tool Shadowing";
const OWASP = "MCP02-tool-poisoning" as const;

const REMEDIATION =
  "Give resources and tools disjoint names. MCP clients route user requests " +
  "to either surface using AI-inferred intent; name collisions create " +
  "confused-deputy primitives where a read-intended request triggers a " +
  "destructive tool. Use distinct prefixes (res_ / tool_ / fetch_ / do_) " +
  "and avoid the common tool-name vocabulary (read_file, write_file, " +
  "execute, delete, send, …) for resource names.";

class ResourceToolShadowingRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { tools: true, resources: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherI5(context);
    if (gathered.facts.length === 0) return [];

    const results: RuleResult[] = [];
    for (const fact of gathered.facts) {
      results.push(this.buildFinding(fact));
    }
    return results;
  }

  private buildFinding(fact: I5Fact): RuleResult {
    const resLoc: Location = {
      kind: "resource",
      uri: fact.resource_uri,
      field: "name",
    };
    const toolLoc: Location = { kind: "tool", tool_name: fact.tool_name };

    const destructive = fact.common_tool_hit?.destructive_by_convention === true;
    const severity: "high" | "critical" = destructive ? "critical" : "high";

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "external-content",
        location: resLoc,
        observed:
          `Resource "${fact.resource_name}" collides with tool ` +
          `"${fact.tool_name}" (match kind: ${fact.match_kind}).`,
        rationale:
          "MCP clients disambiguate tools and resources by protocol endpoint " +
          "at the wire level, but AI clients process both in the same model " +
          "context. When a natural-language request could map to either, " +
          "the client's name-resolution inference can pick the wrong one.",
      })
      .sink({
        sink_type: destructive ? "command-execution" : "privilege-grant",
        location: toolLoc,
        observed:
          destructive
            ? `Tool "${fact.tool_name}" is catalogued as destructive-by-` +
              `convention (${fact.common_tool_hit?.canonical_purpose}).`
            : `Tool "${fact.tool_name}" — canonical purpose ` +
              `${fact.common_tool_hit?.canonical_purpose ?? "(not in common vocabulary)"}.`,
      })
      .impact({
        impact_type: "privilege-escalation",
        scope: "connected-services",
        exploitability: "moderate",
        scenario:
          `A user request that references "${fact.resource_name}" can be ` +
          `routed by the AI client to either the resource (resources/read) ` +
          `or the tool (tools/call). If the tool has destructive side ` +
          `effects, a resource-intended request produces unintended ` +
          `actions without a second confirmation.`,
      })
      .factor(
        "name_collision_confirmed",
        0.1,
        `Case- and separator-normalised name collision between resource ` +
          `"${fact.resource_name}" and tool "${fact.tool_name}" ` +
          `(${fact.match_kind}).`,
      )
      .verification(stepInspectResource(fact))
      .verification(stepInspectTool(fact));

    if (destructive) {
      builder.factor(
        "destructive_tool_vocabulary",
        0.08,
        `Collided tool name is in the destructive-by-convention catalogue ` +
          `(${fact.common_tool_hit?.tool_name}). Severity bumped to critical.`,
      );
    }

    const chain = capConfidence(builder.build(), I5_CONFIDENCE_CAP);
    return {
      rule_id: RULE_ID,
      severity,
      owasp_category: OWASP,
      mitre_technique: null,
      remediation: REMEDIATION,
      chain,
    };
  }
}

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale: `I5 charter caps confidence at ${cap}.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new ResourceToolShadowingRule());

export { ResourceToolShadowingRule };
