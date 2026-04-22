/**
 * A1 — Prompt Injection in Tool Description (Rule Standard v2).
 *
 * Orchestrator for the A1 detection pipeline. Delegates fact-gathering
 * to `gather.ts` (character-level tokenised phrase matching) and
 * aggregates hits via noisy-OR to produce a single evidence-chained
 * finding per tool whose description crosses the confidence floor.
 *
 * Detection technique: linguistic (multi-signal noisy-OR scoring).
 *
 * No regex literals. All phrase / token data lives in
 * `./data/injection-phrases.ts` as typed records.
 */

import type { Severity } from "@mcp-sentinel/database";
import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder } from "../../../evidence.js";
import { gatherA1, toolLocation, type PhraseMatchSite } from "./gather.js";
import {
  stepInspectPrimary,
  stepInspectSecondary,
  stepRemoveDirectives,
} from "./verification.js";

const RULE_ID = "A1";
const RULE_NAME = "Prompt Injection in Tool Description";
const OWASP = "MCP01-prompt-injection";
const MITRE = "AML.T0054";
const CONFIDENCE_CAP = 0.85;
/** Minimum aggregate confidence below which we suppress findings (noise floor). */
const CONFIDENCE_FLOOR = 0.5;

const REMEDIATION =
  "Remove behavioural directives from tool descriptions. Descriptions must " +
  "describe what the tool does (\"Fetches weather data for a city and returns " +
  "the current temperature\"), not instruct the AI how to behave. Specifically: " +
  "(1) delete role-override language (\"ignore previous instructions\"), " +
  "(2) delete authority claims paired with confirmation bypass, (3) delete " +
  "references to prior approvals or other tools' permissions, and (4) delete " +
  "any LLM control tokens or JSON role delimiters. Re-run the scanner to confirm.";

class A1PromptInjectionDescriptionRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "linguistic";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherA1(context);
    const out: RuleResult[] = [];
    for (const [tool_name, hits] of gathered.byTool.entries()) {
      const finding = this.buildFinding(tool_name, hits, context);
      if (finding) out.push(finding);
    }
    return out;
  }

  private buildFinding(
    tool_name: string,
    hits: PhraseMatchSite[],
    context: AnalysisContext,
  ): RuleResult | null {
    // Noisy-OR aggregate: P = 1 - Π(1 - wᵢ)
    const product = hits.reduce((p, h) => p * (1 - h.weight), 1);
    const aggregate = 1 - product;
    if (aggregate < CONFIDENCE_FLOOR) return null;

    // Anchor on the strongest-weighted hit
    const primary = hits.reduce((best, h) => (h.weight > best.weight ? h : best), hits[0]);
    const descLen = findDescriptionLength(context, tool_name);
    const loc = toolLocation(tool_name);

    const severity = severityFromConfidence(aggregate);

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "external-content",
        location: loc,
        observed: primary.observed,
        rationale:
          `Tool description for "${tool_name}" (${descLen} chars) is passed verbatim ` +
          `into the LLM prompt as tool-catalog metadata. It contains ${hits.length} ` +
          `independent injection signal(s). The strongest-weighted match is ` +
          `"${primary.label}" at offset ${primary.offset}. Human reviewers rarely ` +
          `flag prompt-injection language inside tool descriptions; the LLM processes ` +
          `it with tool-metadata-level trust.`,
      })
      .propagation({
        propagation_type: "description-directive",
        location: loc,
        observed:
          `The description string flows from tool metadata into the LLM system prompt ` +
          `without any sanitisation or content filtering at the MCP client boundary. ` +
          `Every signal becomes an independently actionable directive.`,
      })
      .sink({
        sink_type:
          primary.kind === "special-token" || primary.kind === "role-marker"
            ? "code-evaluation"
            : "privilege-grant",
        location: loc,
        observed:
          `${hits.length} injection signal(s) summed via noisy-OR: ` +
          hits
            .slice(0, 4)
            .map((h) => `"${h.label}" (w=${h.weight.toFixed(2)})`)
            .join(", ") +
          (hits.length > 4 ? `, and ${hits.length - 4} more` : ""),
      })
      .impact({
        impact_type: "cross-agent-propagation",
        scope: "ai-client",
        exploitability: aggregate >= 0.8 ? "trivial" : "moderate",
        scenario:
          `Invoking any tool in this server causes the client to include "${tool_name}"'s ` +
          `description (and therefore the injection payload) in the next model prompt. ` +
          `The model can be induced to break role, skip confirmations, leak credentials, ` +
          `or follow hidden instructions on every turn while the server is connected. ` +
          `Documented attack pattern: Rehberger (2024), Invariant Labs (2025).`,
      })
      .factor(
        "tokenised_phrase_match",
        0.08,
        `Deterministic phrase matcher found ${hits.length} independent injection signal(s); ` +
          `primary: "${primary.label}" (weight ${primary.weight.toFixed(2)}).`,
      )
      .factor(
        "noisy_or_base_confidence",
        aggregate - 0.5,
        `Noisy-OR aggregation of ${hits.length} independent weights produced ` +
          `${(aggregate * 100).toFixed(0)}% pre-cap confidence.`,
      );

    if (hits.length >= 3) {
      builder.factor(
        "multi_signal_corroboration",
        0.05,
        `${hits.length} distinct signals — a single paraphrase is unlikely to produce this many.`,
      );
    }

    const specialTokenHit = hits.find((h) => h.kind === "special-token" || h.kind === "role-marker");
    if (specialTokenHit) {
      builder.factor(
        "in_band_control_token",
        0.10,
        `Description contains in-band LLM control token "${specialTokenHit.observed}" — ` +
          `never present in legitimate tool metadata.`,
      );
    }

    builder.reference({
      id: MITRE,
      title: "MITRE ATLAS — AML.T0054 LLM Prompt Injection",
      url: "https://atlas.mitre.org/techniques/AML.T0054",
      relevance:
        "Tool descriptions are a documented direct prompt-injection surface per " +
        "AML.T0054.002. The aggregated phrase signals map to the canonical " +
        "injection payload shapes: role override, confirmation bypass, " +
        "exfiltration directives.",
    });

    builder.verification(stepInspectPrimary(tool_name, primary));
    if (hits.length > 1) {
      builder.verification(stepInspectSecondary(tool_name, hits.filter((h) => h !== primary)));
    }
    builder.verification(stepRemoveDirectives(tool_name));

    const chain = builder.build();
    // Apply charter confidence cap.
    if (chain.confidence > CONFIDENCE_CAP) {
      chain.confidence_factors.push({
        factor: "linguistic_scoring_confidence_cap",
        adjustment: CONFIDENCE_CAP - chain.confidence,
        rationale:
          `A1 charter caps confidence at ${CONFIDENCE_CAP.toFixed(2)} — linguistic ` +
          `scoring of natural language can never match the certainty of a full ` +
          `taint-path proof.`,
      });
      chain.confidence = CONFIDENCE_CAP;
    }

    return {
      rule_id: RULE_ID,
      severity,
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain,
    };
  }
}

function severityFromConfidence(c: number): Severity {
  if (c >= 0.8) return "critical";
  if (c >= 0.6) return "high";
  return "medium";
}

function findDescriptionLength(ctx: AnalysisContext, tool_name: string): number {
  for (const t of ctx.tools ?? []) {
    if (t.name === tool_name) return (t.description ?? "").length;
  }
  return 0;
}

registerTypedRuleV2(new A1PromptInjectionDescriptionRule());

export { A1PromptInjectionDescriptionRule };
