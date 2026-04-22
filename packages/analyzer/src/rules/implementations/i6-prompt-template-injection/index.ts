/**
 * I6 — Prompt Template Injection (Rule Standard v2).
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
import { gatherI6, type I6Fact } from "./gather.js";
import { I6_CONFIDENCE_CAP } from "./data/config.js";
import {
  stepInspectPrompt,
  stepCheckReuseAmplification,
} from "./verification.js";

const RULE_ID = "I6";
const RULE_NAME = "Prompt Template Injection";
const OWASP = "MCP01-prompt-injection" as const;
const MITRE = "AML.T0054";

const REMEDIATION =
  "Sanitise prompt template metadata before exposing it via prompts/get. " +
  "(a) Reject LLM delimiter tokens and role-override phrases in the name, " +
  "description, and argument descriptions. (b) Treat argument descriptions " +
  "with the same care as the top-level description — they are returned " +
  "verbatim alongside the prompt body. (c) Never interpolate server-chosen " +
  "strings into the prompt body via template markers; the template must " +
  "be owned by the prompt AUTHOR, not runtime state.";

class PromptTemplateInjectionRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { prompts: true };
  readonly technique: AnalysisTechnique = "linguistic";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherI6(context);
    if (gathered.facts.length === 0) return [];
    return gathered.facts.map((f) => this.buildFinding(f));
  }

  private buildFinding(fact: I6Fact): RuleResult {
    const promptLoc: Location = {
      kind: "prompt",
      name: fact.prompt_name,
      field: "description",
    };

    const hitDescriptor = fact.hits
      .map((h) => `${h.spec.kind}@${h.matched_field}(${h.key})`)
      .join(", ");

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "external-content",
        location: promptLoc,
        observed: fact.combined_preview,
        rationale:
          "MCP prompt templates are designed to be reused. Injection in the " +
          "template's metadata runs every time the prompt is fetched — the " +
          "abuse scales with invocation frequency without any further " +
          "attacker action.",
      })
      .sink({
        sink_type: "code-evaluation",
        location: promptLoc,
        observed:
          `Injection catalogue hits: ${hitDescriptor}. Aggregate weight: ` +
          `${fact.aggregate_weight.toFixed(2)}.`,
      })
      .impact({
        impact_type: "session-hijack",
        scope: "ai-client",
        exploitability: "trivial",
        scenario:
          `Prompt template "${fact.prompt_name}" contains injection phrasing. ` +
          `Every prompts/get invocation reads the directive as authoritative ` +
          `LLM instruction. The template-reuse amplifier (Invariant Labs 2025) ` +
          `multiplies impact by invocation frequency.`,
      })
      .factor(
        "injection_phrase_matched",
        0.1,
        `Matched ${fact.hits.length} injection-phrase catalogue entries across ` +
          `prompt metadata fields. Noisy-OR aggregate ` +
          `${fact.aggregate_weight.toFixed(2)}.`,
      )
      .reference({
        id: "MITRE-ATLAS-AML.T0054",
        title: "MITRE ATLAS AML.T0054 — LLM Prompt Injection",
        url: "https://atlas.mitre.org/techniques/AML.T0054",
        relevance:
          "Direct prompt injection via the MCP prompts surface.",
      })
      .verification(stepInspectPrompt(fact))
      .verification(stepCheckReuseAmplification(fact));

    const chain = capConfidence(builder.build(), I6_CONFIDENCE_CAP);
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
    rationale: `I6 charter caps confidence at ${cap}.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new PromptTemplateInjectionRule());

export { PromptTemplateInjectionRule };
