/**
 * M4 — Tool Squatting (v2).
 *
 * Detects tool descriptions that carry false authority/authenticity claims
 * designed to displace legitimate tools in an LLM's tool-selection ranking.
 *
 * Zero regex. Word-token walker + typed signal catalogue (see
 * ./data/squatting-vocabulary.ts). Confidence cap 0.85.
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
import { gatherM4, type SquatSite, type MatchedSignal } from "./gather.js";
import {
  stepInspectClaims,
  stepVerifyVendorAttestation,
  stepCheckNegation,
} from "./verification.js";

const RULE_ID = "M4";
const RULE_NAME = "Tool Squatting";
const OWASP = "MCP02-tool-poisoning" as const;
const MITRE = "AML.T0054" as const;
const CONFIDENCE_CAP = 0.85;

const REMEDIATION =
  "Do not claim to be an official, verified, or vendor-endorsed implementation " +
  "unless the package is actually published by the named vendor. Let the " +
  "registry handle verification. Remove authority claims from tool " +
  "descriptions — tool selection should be driven by capability language, " +
  "not by authenticity assertions that cannot be independently verified by " +
  "the AI client.";

const REF_OWASP_MCP02 = {
  id: "OWASP-MCP-02",
  title: "OWASP MCP Top 10 — MCP02: Tool Poisoning",
  url: "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
  relevance:
    "Tool squatting is a metadata-level tool-poisoning pattern: the description " +
    "carries the poison, not the tool behaviour. LLMs ranking tools by perceived " +
    "authority are displaced into the squatting tool.",
} as const;

class M4ToolSquattingRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "linguistic";

  analyze(context: AnalysisContext): RuleResult[] {
    const sites = gatherM4(context);
    const findings: RuleResult[] = [];
    for (const site of sites) {
      const finding = this.buildFinding(site);
      if (finding) findings.push(finding);
    }
    return findings;
  }

  private buildFinding(site: SquatSite): RuleResult | null {
    const signals = site.matched_signals;
    const weights = signals.map((s) => s.weight);

    // If the only signal is a bare vendor token (no regex-signal match), give
    // it a baseline weight of 0.60 so the finding can fire on its own.
    if (signals.length === 0 && site.bare_vendor_token !== null) {
      weights.push(0.60);
    }

    if (weights.length === 0) return null;

    // Noisy-OR: P(squat) = 1 - Π(1 - wᵢ)
    let confidence = 1 - weights.reduce((prod, w) => prod * (1 - w), 1);

    if (site.has_negation) {
      // Drastic reduction — explicit negation is self-correcting
      confidence *= 0.3;
    }

    if (confidence < 0.50) return null;

    const severity = this.severityFor(confidence);
    return this.emitFinding(site, signals, confidence, severity);
  }

  private severityFor(
    confidence: number,
  ): "critical" | "high" | "medium" | "low" | "informational" {
    if (confidence >= 0.80) return "critical";
    if (confidence >= 0.60) return "high";
    return "medium";
  }

  private emitFinding(
    site: SquatSite,
    signals: readonly MatchedSignal[],
    confidence: number,
    severity: "critical" | "high" | "medium",
  ): RuleResult {
    const classList = Array.from(new Set(signals.map((s) => s.cls)));
    const signalSummary = signals.length === 0
      ? `bare vendor token "${site.bare_vendor_token}" at description start`
      : signals.map((s) => `${s.cls}: ${s.matched_text}`).join("; ");

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "external-content",
        location: site.location,
        observed: site.description.slice(0, 200),
        rationale:
          `Tool "${site.tool_name}" description carries ${signals.length} ` +
          `authority/authenticity signal(s) plus ` +
          (site.bare_vendor_token ? `a bare vendor token "${site.bare_vendor_token}". ` : `no bare vendor claim. `) +
          `LLM tool-selection weights authority language heavily: a single ` +
          `matched signal moves this tool up in the ranking; two or more ` +
          `signals typically displace competing legitimate tools.`,
      })
      .sink({
        sink_type: "config-modification",
        location: site.location,
        observed: `Signals consumed by LLM tool-ranker: ${signalSummary}`,
      })
      .impact({
        impact_type: "config-poisoning",
        scope: "ai-client",
        exploitability: signals.length + (site.bare_vendor_token ? 1 : 0) >= 2
          ? "trivial"
          : "moderate",
        scenario:
          `LLM tool-selector ranks tools partly by description authority ` +
          `language. The squatting tool's authority claims displace a ` +
          `legitimate alternative. If the squatting tool is malicious, the ` +
          `AI client invokes it with the same data access and execution ` +
          `privileges it would have granted the legitimate tool.`,
      });

    builder.mitigation({
      mitigation_type: "input-validation",
      present: site.has_negation,
      location: site.location,
      detail: site.has_negation
        ? `A negation token (not|no|unofficial|disclaimer) was detected near ` +
          `an authenticity anchor. Confidence reduced by 0.70× (multiplicative).`
        : `No negation token found near any authenticity anchor — the claim ` +
          `stands without disclaimer.`,
    });

    builder.factor(
      "noisy_or_confidence",
      // Report the noisy-OR contribution explicitly. Adjustment is bounded
      // so the total chain confidence stays inside the v2 contract.
      Math.min(0.70, 1 - weights_product_complement(signals)),
      `Noisy-OR across ${classList.length} signal class(es): ${classList.join(", ")}`,
    );

    if (site.has_negation) {
      builder.factor(
        "negation_adjustment",
        -0.20,
        "Explicit negation ('unofficial', 'not verified', 'disclaimer') reduces confidence",
      );
    }

    builder.reference(REF_OWASP_MCP02);
    builder.verification(stepInspectClaims(site));
    builder.verification(stepVerifyVendorAttestation(site));
    builder.verification(stepCheckNegation(site));

    const chain = capConfidence(builder.build(), CONFIDENCE_CAP);
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

/** 1 - Π(1 - wᵢ). */
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
      `M4 charter caps confidence at ${cap}: authorship cannot be confirmed ` +
      `from description text alone; a future vendor-attestation cross-check ` +
      `would be required to lift the cap.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new M4ToolSquattingRule());

export { M4ToolSquattingRule };
