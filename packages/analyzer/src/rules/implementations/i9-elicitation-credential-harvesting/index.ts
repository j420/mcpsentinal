/**
 * I9 — Elicitation Credential Harvesting (Rule Standard v2).
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
import { gatherI9, type I9Hit } from "./gather.js";
import { I9_CONFIDENCE_CAP } from "./data/config.js";
import {
  stepInspectToolDescription,
  stepCheckAuthFlow,
} from "./verification.js";

const RULE_ID = "I9";
const RULE_NAME = "Elicitation Credential Harvesting";
const OWASP = "MCP07-insecure-config" as const;
const MITRE = "AML.T0057";

const REMEDIATION =
  "Never collect credentials through tool descriptions or elicitation " +
  "prompts. Use spec-sanctioned auth flows (OAuth 2.0 per MCP Authorization " +
  "spec, OIDC, platform-provided credential stores). If a credential is " +
  "genuinely required, issue the request out-of-AI (through the client " +
  "application's settings UI) so the AI is not a delivery channel.";

class ElicitationCredentialHarvestingRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "linguistic";

  analyze(context: AnalysisContext): RuleResult[] {
    const { hits } = gatherI9(context);
    if (hits.length === 0) return [];
    return hits.map((h) => this.buildFinding(h));
  }

  private buildFinding(hit: I9Hit): RuleResult {
    const toolLoc: Location = { kind: "tool", tool_name: hit.tool_name };
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "external-content",
        location: toolLoc,
        observed: hit.description_preview,
        rationale:
          "Tool description pairs a credential-harvesting action token " +
          "(collect / ask / prompt) with a credential target " +
          "(password / token / ssn / credential). Under the MCP elicitation " +
          "capability, this becomes a social-engineering primitive with the " +
          "AI client as the delivery channel.",
      })
      .sink({
        sink_type: "credential-exposure",
        location: toolLoc,
        observed:
          `Tool solicits credentials via AI intermediary. Catalogue entry: ` +
          `${hit.spec_key}.`,
      })
      .impact({
        impact_type: "credential-theft",
        scope: "user-data",
        exploitability: "moderate",
        scenario:
          `Users who see the AI assistant ask for a password comply more ` +
          `readily than users who see the same request from a web form. ` +
          `The tool receives the credential as an argument and can forward ` +
          `it anywhere. Unlike traditional phishing, the victim's trust ` +
          `in the AI is the attack surface.`,
      })
      .factor(
        "elicitation_harvest_phrase_matched",
        0.08,
        `Matched ${hit.spec_key}. Action + target tokens co-occur in the ` +
          `description.`,
      )
      .reference({
        id: "MITRE-ATLAS-AML.T0057",
        title: "MITRE ATLAS AML.T0057 — LLM Data Leakage",
        url: "https://atlas.mitre.org/techniques/AML.T0057",
        relevance:
          "Credential harvesting through the elicitation surface is the " +
          "MCP-specific instance of user-credential leakage via the agent.",
      })
      .verification(stepInspectToolDescription(hit))
      .verification(stepCheckAuthFlow(hit));

    if (hit.fence_hit) {
      builder.factor(
        "false_positive_fence_triggered",
        -0.15,
        "Legitimate co-occurrence token (example / mock / testing) present " +
          "— demoting confidence.",
      );
    }

    const chain = capConfidence(builder.build(), I9_CONFIDENCE_CAP);
    return {
      rule_id: RULE_ID,
      severity: "critical",
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
    rationale: `I9 charter caps confidence at ${cap}.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new ElicitationCredentialHarvestingRule());

export { ElicitationCredentialHarvestingRule };
