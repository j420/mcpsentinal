/**
 * M5 — Context Window Flooding (v2).
 *
 * Detects tools whose descriptions or input schemas promise unbounded /
 * verbose output that can exhaust an AI client's context window and
 * displace safety instructions from the attention region.
 *
 * Zero regex. Word-token walker + typed signal catalogue. Confidence
 * cap 0.80 (see CHARTER.md).
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
import { gatherM5, type FloodSite, type MatchedSignal } from "./gather.js";
import {
  stepInspectDescription,
  stepCheckPagination,
  stepCheckSchemaFlag,
} from "./verification.js";

const RULE_ID = "M5";
const RULE_NAME = "Context Window Flooding";
const OWASP = "MCP01-prompt-injection" as const;
const CONFIDENCE_CAP = 0.80;

const REMEDIATION =
  "Tool responses should be concise by default. Offer explicit pagination " +
  "parameters (limit, offset, cursor) with sensible defaults. Add a " +
  "server-side hard cap on response size. Never return unbounded data sets. " +
  "If the tool intentionally returns verbose output, document the expected " +
  "token cost so an agent planner can budget the call.";

const REF_COSAI_T10 = {
  id: "CoSAI-MCP-T10",
  title: "CoSAI MCP Security — T10: Resource Exhaustion",
  url: "https://www.coalitionforsecureai.org/publications/mcp-threat-taxonomy",
  relevance:
    "Context window is a finite shared resource. An unbounded tool response " +
    "exhausts it and displaces safety instructions out of the attention region.",
} as const;

class M5ContextWindowFloodingRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "linguistic";

  analyze(context: AnalysisContext): RuleResult[] {
    const sites = gatherM5(context);
    const findings: RuleResult[] = [];
    for (const site of sites) {
      const finding = this.buildFinding(site);
      if (finding) findings.push(finding);
    }
    return findings;
  }

  private buildFinding(site: FloodSite): RuleResult | null {
    const signals = site.matched_signals;
    const weights = signals.map((s) => s.weight);
    if (weights.length === 0) return null;

    // Noisy-OR
    let confidence = 1 - weights.reduce((prod, w) => prod * (1 - w), 1);

    // Pagination mitigates (unless the description negates it).
    if (site.has_pagination && !site.has_no_pagination_claim) {
      confidence *= 0.4;
    }

    if (confidence < 0.40) return null;

    const severity = this.severityFor(confidence);
    return this.emitFinding(site, signals, confidence, severity);
  }

  private severityFor(confidence: number): "high" | "medium" | "low" {
    if (confidence >= 0.70) return "high";
    if (confidence >= 0.50) return "medium";
    return "low";
  }

  private emitFinding(
    site: FloodSite,
    signals: readonly MatchedSignal[],
    _confidence: number,
    severity: "high" | "medium" | "low",
  ): RuleResult {
    const classList = Array.from(new Set(signals.map((s) => s.cls)));
    const signalSummary = signals
      .map((s) => `${s.cls}: ${s.matched_text}`)
      .join("; ");

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "external-content",
        location: site.location,
        observed: site.description.slice(0, 200),
        rationale:
          `Tool "${site.tool_name}" description carries ${signals.length} ` +
          `context-flooding signal(s) spanning ${classList.length} class(es). ` +
          `Unbounded output can push safety instructions out of the effective ` +
          `attention region and enable injection amplification.`,
      })
      .sink({
        sink_type: "network-send",
        location: site.location,
        observed: `Signals consumed by AI client context: ${signalSummary}`,
      })
      .impact({
        impact_type: "denial-of-service",
        scope: "ai-client",
        exploitability: signals.length >= 2 ? "moderate" : "complex",
        scenario:
          `Tool response floods the AI client's context window with data. ` +
          `Safety instructions, user context, and prior tool results are ` +
          `pushed out of the attention window. Secondary effects: (1) safety ` +
          `bypass, (2) injection amplification (any attacker text in the ` +
          `flood gets disproportionate weight via recency bias), (3) denial ` +
          `of service (context exhaustion blocks further useful interaction).`,
      });

    const paginationPresent = site.has_pagination && !site.has_no_pagination_claim;
    builder.mitigation({
      mitigation_type: "input-validation",
      present: paginationPresent,
      location: site.schema_location ?? site.location,
      detail: paginationPresent
        ? `Pagination / limit parameter detected — confidence reduced 0.6x.`
        : site.has_no_pagination_claim
          ? `Description explicitly claims "no limit" / "without pagination" — ` +
            `this aggravates the finding rather than mitigating it.`
          : `No pagination parameter found in description or schema.`,
    });

    // Noisy-OR factor
    const noisyOr = Math.min(0.60, 1 - weights_product_complement(signals));
    builder.factor(
      "noisy_or_confidence",
      noisyOr,
      `Noisy-OR across ${classList.length} signal class(es): ${classList.join(", ")}`,
    );

    if (paginationPresent) {
      builder.factor(
        "pagination_mitigation",
        -0.20,
        `Pagination/limit present — reduces confidence multiplicatively.`,
      );
    } else if (site.has_no_pagination_claim) {
      builder.factor(
        "explicit_no_pagination",
        0.10,
        `Description explicitly rejects pagination — aggravates signal.`,
      );
    }

    builder.reference(REF_COSAI_T10);
    builder.verification(stepInspectDescription(site));
    builder.verification(stepCheckPagination(site));
    builder.verification(stepCheckSchemaFlag(site));

    const chain = capConfidence(builder.build(), CONFIDENCE_CAP);
    return {
      rule_id: RULE_ID,
      severity,
      owasp_category: OWASP,
      mitre_technique: null,
      remediation: REMEDIATION,
      chain,
    };
  }
}

function weights_product_complement(signals: readonly MatchedSignal[]): number {
  if (signals.length === 0) return 1;
  let prod = 1;
  for (const s of signals) prod *= 1 - s.weight;
  return prod;
}

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `M5 charter caps confidence at ${cap}: description-only rules cannot ` +
      `prove actual response size. A future Phase-2 runtime measurement ` +
      `would lift the cap.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new M5ContextWindowFloodingRule());

export { M5ContextWindowFloodingRule };
