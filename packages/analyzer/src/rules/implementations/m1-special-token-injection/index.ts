/**
 * M1 — Special Token Injection in Tool Metadata (Rule Standard v2).
 *
 * Deterministic, structural scan of tool name, tool description, and
 * every parameter description for LLM chat-template control tokens
 * (ChatML, Llama, Mistral, GPT, Llama-3 header ids, conversation-role
 * markers). Zero regex literals. Catalogue lives in
 * `./data/special-tokens.ts`.
 *
 * Emits ONE M1 finding per token occurrence. Companions: none — M1 does
 * not shadow H2 (initialize fields) nor A9 (encoded prose); those rules
 * fire independently on their own surfaces.
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
import { gatherM1, type TokenSite } from "./gather.js";
import {
  M1_CONFIDENCE_CAP,
} from "./data/special-tokens.js";
import {
  buildTokenInspectionStep,
  buildTemplateTraceStep,
  buildSanitiserStep,
} from "./verification.js";

const RULE_ID = "M1";
const RULE_NAME = "Special Token Injection in Tool Metadata";
const OWASP = "ASI01-agent-goal-hijack" as const;
const MITRE = "AML.T0054";

const REMEDIATION =
  "Strip LLM chat-template control tokens from tool names, descriptions, " +
  "and parameter descriptions before returning tools/list. Minimum " +
  "catalogue to strip: ChatML (<|im_start|>, <|im_end|>, <|system|>, " +
  "<|assistant|>, <|user|>, <|endoftext|>), Llama ([INST], [/INST], " +
  "<<SYS>>, <</SYS>>, <|begin_of_text|>, <|end_of_text|>, <|eot_id|>, " +
  "<|start_header_id|>, <|end_header_id|>), and line-start conversation " +
  "role markers (System:, Human:, Assistant:). These are control sequences " +
  "the client's chat template absorbs as role boundaries — they are not " +
  "safe content to serialise into a prompt.";

class SpecialTokenInjectionRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    if (!context.tools || context.tools.length === 0) return [];
    const gathered = gatherM1(context);
    if (gathered.sites.length === 0) return [];

    const out: RuleResult[] = [];
    for (const site of gathered.sites) {
      out.push(this.buildFinding(site, gathered.distinct_kinds.size));
    }
    return out;
  }

  private buildFinding(site: TokenSite, distinct_kinds: number): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "external-content",
        location: site.location,
        observed: site.observed,
        rationale:
          `Tool metadata (${site.surface}) contains the literal control ` +
          `token "${site.literal}" (${site.label}). Tool metadata is ` +
          `adversary-controlled content: the server author chooses what ` +
          `goes here, and a malicious or compromised server can embed ` +
          `tokeniser-level control sequences the AI client will propagate ` +
          `into the prompt verbatim.`,
      })
      .propagation({
        propagation_type: "description-directive",
        location: site.location,
        observed:
          `The tools/list response embeds this token in the client's ` +
          `chat-template input. The tokeniser absorbs it at template ` +
          `serialisation time — the token class "${site.kind}" is a ` +
          `role/turn boundary in the corresponding model family's chat ` +
          `template.`,
      })
      .sink({
        sink_type: "code-evaluation",
        location: site.location,
        observed:
          `Model tokeniser treats "${site.literal}" as a role or turn ` +
          `boundary. Bytes that follow are processed at the priority of ` +
          `the newly-opened role (system, instruction, header), bypassing ` +
          `the intended tool-metadata trust boundary.`,
      })
      .mitigation({
        mitigation_type: "input-validation",
        present: false,
        location: site.location,
        detail:
          `No token-stripping sanitiser present on the server's tools/list ` +
          `output for this surface. Legitimate servers strip the known ` +
          `control-token catalogue before returning tool metadata.`,
      })
      .impact({
        impact_type: "cross-agent-propagation",
        scope: "ai-client",
        exploitability: "trivial",
        scenario:
          `An attacker who controls or compromises this MCP server embeds ` +
          `"${site.literal}" in tool metadata. On the next tools/list, the ` +
          `client's chat template absorbs the token as a genuine role ` +
          `boundary, and the attacker gains the ability to inject ` +
          `system-role instructions into the model for the remainder of ` +
          `the session. No user interaction is required beyond listing ` +
          `tools — an action every agent performs on connection.`,
      })
      .factor(
        "special_token_class_count",
        distinct_kinds >= 2 ? 0.1 : 0.0,
        `Server metadata contains tokens from ${distinct_kinds} distinct ` +
          `template families. Multi-family matches suggest deliberate ` +
          `targeting (the attacker does not know which client the user ` +
          `runs, so they plant tokens for several).`,
      )
      .factor(
        "surface_trust_priority",
        site.surface === "tool_name" ? 0.08 : 0.03,
        `Token was found in the ${site.surface} surface. Tool names are ` +
          `the highest-priority surface (rendered first in most templates) ` +
          `so a name-embedded token has the strongest boundary override.`,
      )
      .factor(
        site.fence_hit ? "red_team_fence" : "no_red_team_fence",
        site.fence_hit ? -0.15 : 0.0,
        site.fence_hit
          ? `Metadata mentions red-team / safety-eval context — this is ` +
            `a legitimate subject-matter context for special tokens. ` +
            `Confidence demoted.`
          : `No red-team / safety-eval fence tokens present; the token is ` +
            `unlikely to be legitimate subject-matter content.`,
      )
      .reference({
        id: "MITRE-ATLAS-AML.T0054",
        title: "MITRE ATLAS AML.T0054 — LLM Prompt Injection",
        url: "https://atlas.mitre.org/techniques/AML.T0054",
        relevance:
          "M1 is the static-time detector for special-token injection, " +
          "the tokeniser-level variant of AML.T0054.",
      })
      .verification(buildTokenInspectionStep(site))
      .verification(buildTemplateTraceStep(site))
      .verification(buildSanitiserStep(site));

    const chain = cap(builder.build(), M1_CONFIDENCE_CAP);
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

function cap(chain: EvidenceChain, capVal: number): EvidenceChain {
  if (chain.confidence <= capVal) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: capVal - chain.confidence,
    rationale: `M1 charter caps confidence at ${capVal}.`,
  });
  chain.confidence = capVal;
  return chain;
}

registerTypedRuleV2(new SpecialTokenInjectionRule());

export { SpecialTokenInjectionRule };
