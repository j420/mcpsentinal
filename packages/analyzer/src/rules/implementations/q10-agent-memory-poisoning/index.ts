/** Q10 — Agent Memory Poisoning (v2). Linguistic, zero regex, cap 0.80. */

import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder, type EvidenceChain } from "../../../evidence.js";
import { gatherQ10, type MemorySite, type MatchedSignal } from "./gather.js";
import {
  stepInspectDescription,
  stepCheckMitigation,
  stepTestCanary,
} from "./verification.js";

const RULE_ID = "Q10";
const RULE_NAME = "Agent Memory Poisoning";
const OWASP = "ASI06-memory-context-poisoning" as const;
const MITRE = "AML.T0058" as const;
const CONFIDENCE_CAP = 0.80;

const REMEDIATION =
  "Agent memory should store facts, not behavioural instructions. Validate " +
  "and sanitize stored content. Use append-only memory with expiration, and " +
  "reject writes whose content resembles imperative directives (must|always|" +
  "override|replace). If the tool intentionally exposes a memory write, " +
  "scope it to a dedicated facts-only namespace that the agent's system " +
  "prompt isolates from behavioural context.";

const REF_MITRE_T0058 = {
  id: "MITRE-AML-T0058",
  title: "MITRE ATLAS AML.T0058 — AI Agent Context Poisoning",
  url: "https://atlas.mitre.org/techniques/AML.T0058",
  relevance:
    "Persistent behavioural instructions written to agent memory enable " +
    "cross-session context poisoning — a single write affects every " +
    "subsequent agent session.",
} as const;

class Q10Rule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "linguistic";

  analyze(context: AnalysisContext): RuleResult[] {
    const sites = gatherQ10(context);
    const findings: RuleResult[] = [];
    for (const site of sites) {
      const finding = this.buildFinding(site);
      if (finding) findings.push(finding);
    }
    return findings;
  }

  private buildFinding(site: MemorySite): RuleResult | null {
    const signals = site.matched_signals;
    if (signals.length === 0) return null;

    const classes = new Set(signals.map((s) => s.cls));
    // Multi-signal-required unless one of the signals is the high-impact
    // "system-context-write" class.
    const hasSystemWrite = classes.has("system-context-write");
    if (!hasSystemWrite && classes.size < 2) return null;

    const weights = signals.map((s) => s.weight);
    let confidence = 1 - weights.reduce((prod, w) => prod * (1 - w), 1);

    if (site.has_mitigation) confidence *= 0.35;

    if (confidence < 0.50) return null;

    const severity =
      confidence >= 0.80 ? "critical" as const
      : confidence >= 0.60 ? "high" as const
      : "medium" as const;

    return this.emitFinding(site, signals, confidence, severity);
  }

  private emitFinding(
    site: MemorySite,
    signals: readonly MatchedSignal[],
    _confidence: number,
    severity: "critical" | "high" | "medium",
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
          `Tool "${site.tool_name}" description indicates it writes ` +
          `behavioural content to persistent agent memory: ${signalSummary}. ` +
          `One poisoned write affects every subsequent agent session.`,
      })
      .sink({
        sink_type: "config-modification",
        location: site.location,
        observed: `Behavioural instructions written to persistent agent memory`,
      })
      .mitigation({
        mitigation_type: "input-validation",
        present: site.has_mitigation,
        location: site.location,
        detail: site.has_mitigation
          ? `Memory safety mitigation detected: read-only / append-only / ` +
            `facts-only / sanitize-before-store.`
          : `No memory-safety mitigation — arbitrary behavioural content ` +
            `accepted.`,
      })
      .impact({
        impact_type: "config-poisoning",
        scope: "other-agents",
        exploitability: signals.length >= 2 ? "moderate" : "complex",
        scenario:
          `A compromised upstream tool (or malicious user) injects a ` +
          `persistent instruction via this tool. All future agent sessions ` +
          `that touch the same memory region will observe the instruction ` +
          `and alter behaviour accordingly — overriding safety guidelines, ` +
          `redirecting behaviour, or enabling persistent data exfiltration.`,
      });

    const noisyOr = Math.min(0.60, 1 - weights_product_complement(signals));
    builder.factor(
      "noisy_or_confidence",
      noisyOr,
      `Noisy-OR across ${classList.length} signal class(es): ${classList.join(", ")}`,
    );

    if (site.has_mitigation) {
      builder.factor(
        "mitigation_adjustment",
        -0.25,
        "Memory-safety mitigation present — confidence reduced",
      );
    }

    builder.reference(REF_MITRE_T0058);
    builder.verification(stepInspectDescription(site));
    builder.verification(stepCheckMitigation(site));
    builder.verification(stepTestCanary(site));

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
      `Q10 charter caps confidence at ${cap}: description cannot prove ` +
      `whether stored content is factual or behavioural.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new Q10Rule());
export { Q10Rule };
