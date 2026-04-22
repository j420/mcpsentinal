/**
 * J5 — Tool Output Poisoning Patterns (Rule Standard v2).
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
import { gatherJ5, type J5Hit } from "./gather.js";
import { J5_CONFIDENCE_CAP } from "./data/config.js";
import {
  stepInspectResponseConstruction,
  stepTestRuntime,
} from "./verification.js";

const RULE_ID = "J5";
const RULE_NAME = "Tool Output Poisoning Patterns";
const OWASP = "MCP01-prompt-injection" as const;
const MITRE = "AML.T0054.001";

const REMEDIATION =
  "Tool responses must NEVER contain behavioural directives for the AI. " +
  "Strip LLM-style imperative tokens (\"please\", \"you should\", \"ignore " +
  "previous\") from runtime error/response construction. When a runtime " +
  "response must convey diagnostic data, wrap it in delimited [EXTERNAL " +
  "OUTPUT] blocks so the client can tag it as low-trust. Reference " +
  "CyberArk ATPA (2025) for the canonical attack demonstration.";

class ToolOutputPoisoningRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const { hits } = gatherJ5(context);
    return hits.map((h) => this.buildFinding(h));
  }

  private buildFinding(hit: J5Hit): RuleResult {
    const loc: Location = {
      kind: "source",
      file: "<server source>",
      line: hit.line_number,
    };

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: loc,
        observed: hit.line_preview,
        rationale:
          "Source code constructs a response / error message containing " +
          "behavioural directives for the AI client. At runtime the " +
          "directive reaches the AI context and is processed as trusted " +
          "tool output — bypassing static description scanning entirely.",
      })
      .propagation({
        propagation_type: "function-call",
        location: loc,
        observed:
          "Static construction → runtime response → AI context ingestion.",
      })
      .sink({
        sink_type: "code-evaluation",
        location: loc,
        observed: `Manipulation kind: ${hit.spec.kind}.`,
      })
      .impact({
        impact_type: "session-hijack",
        scope: "ai-client",
        exploitability: "moderate",
        scenario:
          "When the AI invokes the tool and receives the manipulated " +
          "response, it follows the embedded directive — reading " +
          "credentials, invoking an attacker-specified tool, or overriding " +
          "role assignments. CyberArk ATPA (2025) demonstrated this.",
      })
      .factor(
        "manipulation_tokens_in_response",
        0.1,
        `Matched ${hit.spec_key} (${hit.spec.kind}) — response + ` +
          `instruction + target tokens on the same line.`,
      )
      .reference({
        id: "CyberArk-ATPA-2025",
        title: "CyberArk — Automated Tool Poisoning Attack",
        url: "https://www.cyberark.com/resources/threat-research-blog/automated-tool-poisoning-attack",
        year: 2025,
        relevance:
          "Demonstrated runtime tool-output poisoning bridging the " +
          "static/dynamic analysis gap.",
      })
      .verification(stepInspectResponseConstruction(hit))
      .verification(stepTestRuntime());

    const chain = capConfidence(builder.build(), J5_CONFIDENCE_CAP);
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
    rationale: `J5 charter caps confidence at ${cap}.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new ToolOutputPoisoningRule());

export { ToolOutputPoisoningRule };
