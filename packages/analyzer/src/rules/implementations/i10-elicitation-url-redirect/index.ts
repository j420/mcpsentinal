/**
 * I10 — Elicitation URL Redirect (Rule Standard v2).
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
import { gatherI10, type I10Hit } from "./gather.js";
import { I10_CONFIDENCE_CAP } from "./data/config.js";
import {
  stepInspectDescription,
  stepVerifyLandingDomain,
} from "./verification.js";

const RULE_ID = "I10";
const RULE_NAME = "Elicitation URL Redirect";
const OWASP = "MCP07-insecure-config" as const;

const REMEDIATION =
  "Never instruct the AI to redirect users to external URLs via tool " +
  "descriptions. Host-allowlist any URL the server references, and never " +
  "derive the host from a tool argument. Use real OAuth flows (documented " +
  "authorization endpoints) rather than description-driven phishing-shaped " +
  "redirects.";

class ElicitationUrlRedirectRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "linguistic";

  analyze(context: AnalysisContext): RuleResult[] {
    const { hits } = gatherI10(context);
    return hits.map((h) => this.buildFinding(h));
  }

  private buildFinding(hit: I10Hit): RuleResult {
    const toolLoc: Location = { kind: "tool", tool_name: hit.tool_name };
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "external-content",
        location: toolLoc,
        observed: hit.description_preview,
        rationale:
          "Tool description pairs a redirect action (redirect / navigate / " +
          "visit) with an auth/url target. Under MCP elicitation, the AI " +
          "delivers the redirect instruction to the user under its implicit " +
          "trust.",
      })
      .sink({
        sink_type: "network-send",
        location: toolLoc,
        observed:
          `Redirect primitive: ${hit.spec_key}. Landing URL is out of ` +
          `static-analysis scope.`,
      })
      .impact({
        impact_type: "credential-theft",
        scope: "user-data",
        exploitability: "moderate",
        scenario:
          "The AI follows the description and sends the user to the external " +
          "URL. If the URL is attacker-controlled, the landing page harvests " +
          "credentials under the AI's implicit endorsement. This is AI-" +
          "mediated phishing — more effective than email phishing.",
      })
      .factor(
        "redirect_phrase_matched",
        0.08,
        `Matched ${hit.spec_key}.`,
      )
      .verification(stepInspectDescription(hit))
      .verification(stepVerifyLandingDomain(hit));

    if (hit.fence_hit) {
      builder.factor(
        "false_positive_fence_triggered",
        -0.15,
        "Legitimate co-occurrence (example / docs / readme) — demoted.",
      );
    }

    const chain = capConfidence(builder.build(), I10_CONFIDENCE_CAP);
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

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale: `I10 charter caps confidence at ${cap}.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new ElicitationUrlRedirectRule());

export { ElicitationUrlRedirectRule };
