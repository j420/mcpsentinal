/** M2 — Prompt Leaking via Tool Response (v2). AST-only; zero regex; cap 0.80. */

import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder, type EvidenceChain } from "../../../evidence.js";
import { gatherM2, type LeakSite } from "./gather.js";
import {
  stepInspectReturn,
  stepCheckRedaction,
  stepCheckConfig,
} from "./verification.js";

const RULE_ID = "M2";
const OWASP = "MCP04-data-exfiltration" as const;
const MITRE = "AML.T0057" as const;
const CONFIDENCE_CAP = 0.80;

const REMEDIATION =
  "Never include system-prompt identifiers in tool responses. Introduce a " +
  "redact/strip/mask helper applied at the single response boundary, and " +
  "make it impossible to construct the response without that helper (a " +
  "type-level guard in TypeScript, or a response schema with the prompt " +
  "field explicitly absent).";

const REF_MITRE_T0057 = {
  id: "MITRE-AML-T0057",
  title: "MITRE ATLAS AML.T0057 — LLM Data Leakage",
  url: "https://atlas.mitre.org/techniques/AML.T0057",
  relevance:
    "System prompts contain proprietary instructions; leaking them enables " +
    "downstream prompt-injection and intellectual-property exfiltration.",
} as const;

class M2Rule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = "Prompt Leaking via Tool Response";
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "ast-taint";

  analyze(context: AnalysisContext): RuleResult[] {
    const sites = gatherM2(context);
    return sites.map((s) => this.buildFinding(s));
  }

  private buildFinding(site: LeakSite): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "environment",
        location: site.location,
        observed: `System prompt identifier: ${site.identifier}`,
        rationale:
          `Identifier "${site.identifier}" holds the server's system prompt. ` +
          `The AST walker found it inside a data-flow path that ends in a ` +
          `response sink or return statement.`,
      })
      .propagation({
        propagation_type: "variable-assignment",
        location: site.location,
        observed: site.observed,
      })
      .sink({
        sink_type: "network-send",
        location: site.location,
        observed: `System prompt leaves the server via tool response`,
      })
      .mitigation({
        mitigation_type: "sanitizer-function",
        present: site.enclosing_has_redaction,
        location: site.enclosing_function_location ?? site.location,
        detail: site.enclosing_has_redaction
          ? `Redact / mask / sanitize / filter found in enclosing scope.`
          : `No redaction / mask / sanitize / filter in enclosing scope.`,
      })
      .impact({
        impact_type: "data-exfiltration",
        scope: "connected-services",
        exploitability: "trivial",
        scenario:
          `Attacker invokes the tool, receives the system prompt in the ` +
          `response, extracts proprietary instructions and safety rules, ` +
          `and crafts targeted prompt-injection payloads that reliably ` +
          `bypass the documented safety behaviours.`,
      })
      .factor(
        "prompt_in_return_path",
        0.14,
        `"${site.identifier}" flows into response via AST-verified data path`,
      );

    builder.reference(REF_MITRE_T0057);
    builder.verification(stepInspectReturn(site));
    builder.verification(stepCheckRedaction(site));
    builder.verification(stepCheckConfig(site));

    const chain = capConfidence(builder.build(), CONFIDENCE_CAP);
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

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale: `M2 cap ${cap}: AST cannot prove the identifier's runtime value is the system prompt.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new M2Rule());
export { M2Rule };
