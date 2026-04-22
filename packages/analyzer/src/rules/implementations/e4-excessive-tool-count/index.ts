/**
 * E4 — Excessive Tool Count (v2)
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
import { gatherE4, type ToolCountObservation } from "./gather.js";
import {
  stepCountTools,
  stepCrossRefI16,
  stepProposeSplit,
} from "./verification.js";

const RULE_ID = "E4";
const RULE_NAME = "Excessive Tool Count";
const OWASP = "MCP06-excessive-permissions" as const;
const MITRE: string | null = null;
const CONFIDENCE_CAP = 0.65;

const REMEDIATION =
  "Reduce the exposed tool count by splitting the server into focused sub-servers. Each " +
  "sub-server should cover a cohesive permission scope (≤20 tools per scope is a reasonable " +
  "default). This restores per-tool scrutiny at consent time and defeats the Invariant-Labs " +
  "consent-fatigue attack shape. Where splitting is impractical, document the rationale and " +
  "require explicit per-tool consent in the MCP client.";

const REF_INVARIANT_LABS = {
  id: "INVARIANT-LABS-CONSENT-FATIGUE-2025",
  title: "Invariant Labs — Consent Fatigue in MCP Tool Approval (2025)",
  url: "https://invariantlabs.ai/blog/consent-fatigue-in-mcp",
  year: 2025,
  relevance:
    "Invariant Labs measured 84.2% tool poisoning success against MCP servers exposing many " +
    "benign tools + a few dangerous ones under auto-approve. E4 is the static mirror: a high " +
    "tool count is the precondition the attack exploits.",
} as const;

class ExcessiveToolCountRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { tools: true, min_tools: 51 };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherE4(context);
    if (!gathered.observation) return [];
    return [this.buildFinding(gathered.observation)];
  }

  private buildFinding(obs: ToolCountObservation): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "environment",
        location: obs.capabilityLocation,
        observed:
          `Server exposes ${obs.count} tools (threshold: 50). Tool count alone is a risk ` +
          `multiplier; Invariant Labs measured 84.2% consent-bypass success under auto-approve ` +
          `on servers this large.`,
        rationale:
          "Every tool is a permission the user must individually approve. As the list grows past " +
          "the limit of human attention, users lean on auto-approve; any dangerous tool hidden " +
          "in the list executes without scrutiny.",
      })
      .sink({
        sink_type: "privilege-grant",
        location: obs.capabilityLocation,
        observed:
          `${obs.count} tool permissions are consented to in aggregate rather than individually. ` +
          `A dangerous-by-design or poisoned-description tool in the set is effectively ` +
          `auto-approved.`,
      })
      .impact({
        impact_type: "privilege-escalation",
        scope: "ai-client",
        exploitability: "moderate",
        scenario:
          `The user grants server consent once and thereby authorises every one of the ${obs.count} ` +
          `tools. A compromised or malicious tool in the set (classic I16 attack shape) executes ` +
          `with the server's delegated authority on any ambiguous prompt.`,
      })
      .factor(
        "tool_count_over_threshold",
        obs.isExcessive ? 0.1 : 0.05,
        `Tool count ${obs.count} exceeds the ` +
          (obs.isExcessive
            ? `EXCESSIVE threshold (100+).`
            : `50-tool baseline but is below the excessive tier.`),
      );

    builder.reference(REF_INVARIANT_LABS);
    builder.verification(stepCountTools(obs));
    builder.verification(stepCrossRefI16(obs));
    builder.verification(stepProposeSplit(obs));

    const chain = capConfidence(builder.build(), CONFIDENCE_CAP);

    return {
      rule_id: RULE_ID,
      severity: "medium",
      owasp_category: OWASP,
      mitre_technique: MITRE,
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
    rationale:
      `E4 charter caps confidence at ${cap}. Tool count is a policy-dependent signal; some ` +
      `domains legitimately expose >50 tools (complex IDE-integrated servers, comprehensive ` +
      `toolchains).`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new ExcessiveToolCountRule());

export { ExcessiveToolCountRule };
