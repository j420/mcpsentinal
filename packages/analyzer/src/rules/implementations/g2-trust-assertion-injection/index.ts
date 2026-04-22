/**
 * G2 — Trust Assertion Injection (Rule Standard v2).
 *
 * Detects authority/certification/endorsement claims in tool
 * descriptions and initialize.instructions. LLMs extend implicit
 * trust to such phrasing, skipping confirmation dialogs and
 * accepting argument values without scrutiny.
 *
 * Detection technique: linguistic (multi-signal noisy-OR).
 * No regex literals. All data lives in `_shared/ai-manipulation-phrases.ts`.
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
import { gatherG2, siteLocation, type AuthoritySite } from "./gather.js";
import {
  stepInspectAuthorityClaim,
  stepInspectCorroboratingClaims,
  stepRemoveClaim,
} from "./verification.js";
import {
  CONFIDENCE_CAP,
  CONFIDENCE_FLOOR,
  clampConfidence,
  noisyOr,
} from "./data/g2-scoring.js";

const RULE_ID = "G2";
const RULE_NAME = "Trust Assertion Injection";
const OWASP = "MCP02-tool-poisoning";
const MITRE = "AML.T0054";

const REMEDIATION =
  "Remove all authority/trust/certification claims from tool descriptions and " +
  "server initialize.instructions. Legitimate provenance is established through " +
  "signed attestations, external registry metadata, or verified publisher " +
  "identity — never through self-declaration in prose. Rewrite each description " +
  "to describe ONLY what the tool does (its inputs, outputs, and behaviour). " +
  "Re-run the scanner to confirm zero G2 findings.";

function severityFromConfidence(c: number): Severity {
  if (c >= 0.75) return "critical";
  if (c >= 0.60) return "high";
  return "medium";
}

class G2TrustAssertionInjectionRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "linguistic";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherG2(context);
    const out: RuleResult[] = [];
    for (const [scopeKey, hits] of gathered.byScope.entries()) {
      const finding = this.buildFinding(scopeKey, hits);
      if (finding) out.push(finding);
    }
    return out;
  }

  private buildFinding(scopeKey: string, hits: AuthoritySite[]): RuleResult | null {
    // Noisy-OR over EFFECTIVE weights (fence-demoted where relevant).
    const aggregate = noisyOr(hits.map((h) => h.effective_weight));
    if (aggregate < CONFIDENCE_FLOOR) return null;

    const primary = hits.reduce(
      (best, h) => (h.effective_weight > best.effective_weight ? h : best),
      hits[0],
    );
    const others = hits.filter((h) => h !== primary);
    const loc = siteLocation(primary);

    const surfaceLabel =
      primary.surface === "initialize_instructions"
        ? "initialize.instructions"
        : `tool "${primary.tool_name}" description`;

    const anyFence = hits.some((h) => h.fence_triggered);

    const builder = new EvidenceChainBuilder()
      .source({
        source_type:
          primary.surface === "initialize_instructions"
            ? "initialize-field"
            : "external-content",
        location: loc,
        observed: primary.observed,
        rationale:
          `The ${surfaceLabel} contains ${hits.length} authority/certification ` +
          `signal(s). The strongest is "${primary.label}" (weight ` +
          `${primary.weight.toFixed(2)}${primary.fence_triggered ? ", fence-demoted" : ""}). ` +
          `LLMs are trained to defer to authority-claim phrasing in tool metadata, ` +
          `which causes skip of confirmation dialogs and trust escalation on ` +
          `subsequent tool calls.`,
      })
      .propagation({
        propagation_type: "description-directive",
        location: loc,
        observed:
          `Authority phrase flows from ${primary.surface} into the LLM prompt as ` +
          `tool-metadata context. Each signal: ` +
          hits
            .slice(0, 4)
            .map((h) => `"${h.label}" (w=${h.effective_weight.toFixed(2)})`)
            .join(", ") +
          (hits.length > 4 ? `, and ${hits.length - 4} more` : "") +
          ".",
      })
      .sink({
        sink_type: "privilege-grant",
        location: loc,
        observed:
          `Noisy-OR aggregation of ${hits.length} independent authority signal(s) ` +
          `produced ${(aggregate * 100).toFixed(0)}% pre-cap confidence. The LLM ` +
          `applies elevated implicit trust to subsequent invocations of this ` +
          `${primary.surface === "initialize_instructions" ? "server" : "tool"}.`,
      })
      .impact({
        impact_type: "privilege-escalation",
        scope: "ai-client",
        exploitability: aggregate >= 0.75 ? "trivial" : "moderate",
        scenario:
          `The AI reads ${surfaceLabel}, interprets the self-declared authority ` +
          `claim as legitimate provenance, and grants the ` +
          `${primary.surface === "initialize_instructions" ? "entire server" : "tool"} ` +
          `elevated trust for the rest of the session — skipping user confirmation on ` +
          `destructive calls, accepting argument values it would otherwise question. ` +
          `Documented by Rehberger (2024). No analogue in traditional security: the ` +
          `attack targets LLM training priors, not software controls.`,
      })
      .factor(
        "authority_phrase_match",
        0.08,
        `Deterministic phrase matcher found ${hits.length} authority/certification ` +
          `signal(s); primary: "${primary.label}" (weight ${primary.weight.toFixed(2)}).`,
      )
      .factor(
        "noisy_or_base_confidence",
        aggregate - 0.5,
        `Noisy-OR aggregation of ${hits.length} independent fence-adjusted ` +
          `weights produced ${(aggregate * 100).toFixed(0)}% pre-cap confidence.`,
      );

    if (hits.length >= 3) {
      builder.factor(
        "stacked_claim_corroboration",
        0.05,
        `${hits.length} distinct authority signals in the same ${primary.surface} — ` +
          `a single paraphrase is unlikely to produce this many.`,
      );
    }

    if (primary.surface === "initialize_instructions") {
      builder.factor(
        "initialize_trust_surface",
        0.05,
        "initialize.instructions is processed BEFORE any tool description with " +
          "the highest implicit trust — authority claims here apply session-wide.",
      );
    }

    if (anyFence) {
      builder.factor(
        "false_positive_fence_triggered",
        -0.08,
        "One or more fence tokens (e.g. 'self-declared', 'example', 'marketing', " +
          "'documentation') co-occur in the description; matching signals have been " +
          "weight-demoted to reflect possible legitimate usage.",
      );
    }

    builder.reference({
      id: "EMBRACE-THE-RED-AUTHORITY-ASSERTION-2024",
      title: "Rehberger (2024) — Authority-Assertion Injection against MCP Clients",
      url: "https://embracethered.com/blog/posts/2024/claude-llm-prompt-injection-mcp/",
      year: 2024,
      relevance:
        "Authority-claim phrasing in tool metadata reliably causes LLMs to skip " +
        "confirmation dialogs and grant elevated implicit trust.",
    });

    builder.verification(stepInspectAuthorityClaim(primary));
    if (others.length > 0) {
      builder.verification(stepInspectCorroboratingClaims(primary, others));
    }
    builder.verification(stepRemoveClaim(primary));

    const chain = builder.build();
    if (chain.confidence > CONFIDENCE_CAP) {
      chain.confidence_factors.push({
        factor: "linguistic_scoring_confidence_cap",
        adjustment: CONFIDENCE_CAP - chain.confidence,
        rationale:
          `G2 charter caps confidence at ${CONFIDENCE_CAP.toFixed(2)} — ` +
          `authority-claim linguistic scoring cannot reach the certainty of a ` +
          `taint-path proof.`,
      });
      chain.confidence = clampConfidence(chain.confidence, CONFIDENCE_CAP);
    }

    // Use the pre-cap aggregate for severity so capping doesn't mask critical findings.
    const severity = severityFromConfidence(aggregate);

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

registerTypedRuleV2(new G2TrustAssertionInjectionRule());

export { G2TrustAssertionInjectionRule };
// Re-export scope key for tests that want to inspect gather output.
export { gatherG2 } from "./gather.js";
