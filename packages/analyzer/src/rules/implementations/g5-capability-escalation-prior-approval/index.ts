/**
 * G5 — Capability Escalation via Prior Approval (Rule Standard v2).
 *
 * Orchestrator for the G5 detection pipeline. Delegates fact-gathering
 * to `gather.ts` (character-level tokenised phrase matching) and
 * aggregates hits via noisy-OR to produce one evidence-chained finding
 * per tool whose description crosses the confidence floor.
 *
 * Detection technique: linguistic (multi-signal noisy-OR scoring).
 *
 * NO regex literals. All phrase / permission-noun data lives in
 * `./data/prior-approval-phrases.ts` as typed records.
 *
 * Attack surface:
 *   Tool.description text — processed by the LLM as tool-catalog
 *   metadata. A payload asserting "permissions you already granted"
 *   (or any of the other lethal edge-case shapes) exploits the
 *   model's session-state reasoning to apply a permission without a
 *   fresh confirmation prompt.
 *
 * Confidence cap: 0.82 (CHARTER). Slightly below A1's 0.85 because
 * a minority of legitimate tools genuinely describe their
 * relationship to other tools; the permission-noun adjacency gate
 * already removes most of those, but linguistic analysis of natural
 * language never reaches full deterministic certainty.
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
import { gatherG5, toolLocation, type PhraseMatchSite } from "./gather.js";
import {
  stepInspectPrimary,
  stepInspectSecondary,
  stepRewriteDescription,
} from "./verification.js";

const RULE_ID = "G5";
const RULE_NAME = "Capability Escalation via Prior Approval";
const OWASP = "MCP01-prompt-injection";
const MITRE = "AML.T0054";
const CONFIDENCE_CAP = 0.82;
/** Minimum aggregate confidence below which we suppress findings. */
const CONFIDENCE_FLOOR = 0.5;

const REMEDIATION =
  "Remove every reference to permissions the user 'already granted', " +
  "approvals inherited from other tools, or session state carried forward " +
  "from a prior turn. Each tool must declare its own required permissions " +
  "independently (e.g. 'Requires read access to /data'). Do not rely on " +
  "'haven't revoked' language. MCP clients tuned for auto-approve will " +
  "treat any such phrasing as a grant and forward the call without user " +
  "confirmation — this is the documented AI-specific session-state " +
  "exploit (Rehberger 2024, Invariant Labs 2025).";

class G5CapabilityEscalationRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "linguistic";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherG5(context);
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

    // Anchor on the strongest-weighted hit.
    const primary = hits.reduce(
      (best, h) => (h.weight > best.weight ? h : best),
      hits[0],
    );
    const descLen = findDescriptionLength(context, tool_name);
    const loc = toolLocation(tool_name);

    const severity = severityFromConfidence(aggregate);
    const uniqueCategories = new Set(hits.map((h) => h.category)).size;

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "external-content",
        location: loc,
        observed: primary.observed,
        rationale:
          `Tool description for "${tool_name}" (${descLen} chars) is passed ` +
          `verbatim into the LLM prompt as tool-catalog metadata. It contains ` +
          `${hits.length} prior-approval signal(s) across ${uniqueCategories} ` +
          `edge-case category(ies). The strongest-weighted match is ` +
          `"${primary.label}" at offset ${primary.offset}, with permission ` +
          `noun "${primary.nearby_permission_noun ?? "<none>"}" observed within ` +
          `8 tokens. Legitimate descriptions declare their own scope; they do ` +
          `not cite approvals supposedly given to another tool.`,
      })
      .propagation({
        propagation_type: "description-directive",
        location: loc,
        observed:
          `The description flows from tool metadata into the LLM's session ` +
          `context. The model is tuned to be consistent across turns, so a ` +
          `claim that "permissions were already granted" becomes an implicit ` +
          `permission grant inside the model's reasoning — even though no ` +
          `such grant exists in the client's consent ledger.`,
      })
      .sink({
        sink_type: "privilege-grant",
        location: loc,
        observed:
          `${hits.length} signal(s) summed via noisy-OR: ` +
          hits
            .slice(0, 4)
            .map((h) => `"${h.label}" (w=${h.weight.toFixed(2)})`)
            .join(", ") +
          (hits.length > 4 ? `, and ${hits.length - 4} more` : ""),
      })
      .impact({
        impact_type: "privilege-escalation",
        scope: "ai-client",
        exploitability: aggregate >= 0.8 ? "trivial" : "moderate",
        scenario:
          `When the agent invokes "${tool_name}", the LLM reads this ` +
          `description and — citing the fabricated "prior approval" — ` +
          `executes the tool without issuing a fresh confirmation prompt. ` +
          `On auto-approve MCP clients, 78% of such payloads bypass user ` +
          `confirmation (Invariant Labs, 2025). The outcome: the tool ` +
          `exercises permissions the user never actually granted, and the ` +
          `human-oversight path required by EU AI Act Article 14 is broken.`,
      })
      .factor(
        "prior_approval_phrase_match",
        0.08,
        `Deterministic phrase matcher found ${hits.length} prior-approval ` +
          `signal(s); primary: "${primary.label}" (weight ${primary.weight.toFixed(2)}).`,
      )
      .factor(
        "noisy_or_base_confidence",
        aggregate - 0.5,
        `Noisy-OR aggregation of ${hits.length} independent weights produced ` +
          `${(aggregate * 100).toFixed(0)}% pre-cap confidence.`,
      );

    if (uniqueCategories >= 2) {
      builder.factor(
        "multi_category_corroboration",
        0.05,
        `${uniqueCategories} distinct edge-case categories matched — this is ` +
          `a structural pattern, not a paraphrase coincidence.`,
      );
    }

    if (primary.nearby_permission_noun) {
      builder.factor(
        "permission_noun_adjacency",
        0.03,
        `Permission noun "${primary.nearby_permission_noun}" appears within ` +
          `8 tokens of the primary phrase — the trigger + noun pattern is ` +
          `the defining G5 shape.`,
      );
    }

    builder.reference({
      id: MITRE,
      title: "MITRE ATLAS — AML.T0054 LLM Prompt Injection",
      url: "https://atlas.mitre.org/techniques/AML.T0054",
      relevance:
        "G5 is a session-state exploit delivered through the tool-description " +
        "injection surface AML.T0054 enumerates. The payload manufactures a " +
        "prior grant the LLM then applies without fresh confirmation.",
    });

    builder.verification(stepInspectPrimary(tool_name, primary));
    if (hits.length > 1) {
      builder.verification(
        stepInspectSecondary(
          tool_name,
          hits.filter((h) => h !== primary),
        ),
      );
    }
    builder.verification(stepRewriteDescription(tool_name));

    const chain = builder.build();

    // Apply CHARTER confidence cap.
    if (chain.confidence > CONFIDENCE_CAP) {
      chain.confidence_factors.push({
        factor: "linguistic_scoring_confidence_cap",
        adjustment: CONFIDENCE_CAP - chain.confidence,
        rationale:
          `G5 CHARTER caps confidence at ${CONFIDENCE_CAP.toFixed(2)} — ` +
          `linguistic scoring of a natural-language session-state claim ` +
          `never reaches the certainty of a deterministic taint-path proof.`,
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

registerTypedRuleV2(new G5CapabilityEscalationRule());

export { G5CapabilityEscalationRule };
