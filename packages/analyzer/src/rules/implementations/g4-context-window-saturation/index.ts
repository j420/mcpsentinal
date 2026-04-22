/**
 * G4 — Context Window Saturation (Rule Standard v2).
 *
 * Structural detection of oversized, padded, or tail-payload-carrying tool
 * descriptions that push the MCP client's safety instructions below the
 * model's effective attention threshold.
 *
 * This rule is deliberately structural (length, ratios, positions,
 * repetition signatures) — the attack works independent of WHAT the
 * padding says, so phrase-matching alone is the wrong lens.
 *
 * Confidence cap: 0.78 (see CHARTER.md).
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder } from "../../../evidence.js";
import {
  gatherG4,
  toolLocation,
  attentionSinkLocation,
  type SiteSignals,
  type SaturationSignal,
} from "./gather.js";
import {
  buildLongDescriptionSourceStep,
  buildPeerZscoreStep,
  buildTailPayloadStep,
  buildRepetitionStep,
  buildImpactStep,
} from "./verification.js";
import { CONTEXT_SATURATION_THRESHOLDS as T } from "./data/context-saturation-thresholds.js";

const RULE_ID = "G4";
const RULE_NAME = "Context Window Saturation";
const OWASP = "MCP01-prompt-injection";
const MITRE = "AML.T0058";

const REMEDIATION =
  "Keep tool descriptions under 500 characters for simple tools, 1000 for " +
  "complex ones, and proportional to declared parameters (≤150 chars/param). " +
  "Do not pad descriptions with repeated disclaimers, lengthy boilerplate, " +
  "or duplicated lines. Enforce a per-tool description length cap at the " +
  "MCP client or gateway. Oversized descriptions push safety instructions " +
  "below the model's effective attention threshold; tail-payload injection " +
  "attacks rely on exactly that displacement.";

class G4Rule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    return gatherG4(context).map((s) => this.buildFinding(s));
  }

  private buildFinding(site: SiteSignals): RuleResult {
    const loc = toolLocation(site.tool_name);
    const sinkLoc = attentionSinkLocation();

    const builder = new EvidenceChainBuilder();

    // Source: the oversized description itself.
    builder.source({
      source_type: "external-content",
      location: loc,
      observed:
        `Tool "${site.tool_name}" has a ${site.description_length}-byte ` +
        `description across ${site.parameter_count} declared parameter(s) ` +
        `(${site.description_parameter_ratio.toFixed(0)} bytes/param).`,
      rationale:
        `Tool descriptions are external content authored by the server ` +
        `publisher. A description sized beyond the legitimate documentation ` +
        `budget for its parameter count is the structural precondition for ` +
        `a context-window saturation attack.`,
    });

    // Propagation: description → model context → attention displacement.
    builder.propagation({
      propagation_type: "description-directive",
      location: loc,
      observed:
        `All ${site.description_length} bytes are concatenated into the ` +
        `MCP client's tool-catalogue block and delivered to the model on ` +
        `every turn in which this tool is eligible. Recency bias places ` +
        `the last ${Math.round(T.tail_fraction * 100)}% of the description ` +
        `at maximum effective attention weight.`,
    });

    // Sink: the model's attention mechanism.
    builder.sink({
      sink_type: "code-evaluation",
      location: sinkLoc,
      observed:
        `Safety instructions placed before this description in the context ` +
        `window are displaced below the model's effective attention ` +
        `threshold. The tail of the description sits at maximum recency ` +
        `weight — the canonical placement for a payload.`,
    });

    // Impact link.
    const hasTail = site.signals.includes("tail_imperative_density");
    builder.impact({
      impact_type: "cross-agent-propagation",
      scope: "ai-client",
      exploitability: hasTail ? "trivial" : "moderate",
      scenario:
        `An injection payload positioned in the tail of a saturated ` +
        `${site.description_length}-byte description exploits LLM recency ` +
        `bias to override earlier safety instructions. The attack succeeds ` +
        `even when the padding itself is semantically benign — WHERE the ` +
        `payload sits matters more than WHAT the padding says.`,
    });

    // Per-signal confidence factors.
    addSignalFactors(builder, site);

    // Real-world reference.
    builder.reference({
      id: "MITRE-ATLAS-AML-T0058",
      title: "MITRE ATLAS AML.T0058 — AI Agent Context Poisoning",
      url: "https://atlas.mitre.org/techniques/AML.T0058",
      relevance:
        "Context-window saturation via padded tool descriptions is the " +
        "MCP-specific instance of ATLAS AML.T0058 context poisoning.",
    });

    // Verification steps.
    builder.verification(buildLongDescriptionSourceStep(site));
    builder.verification(buildPeerZscoreStep(site));
    builder.verification(buildTailPayloadStep(site));
    if (site.signals.includes("repetitive_padding")) {
      builder.verification(buildRepetitionStep(site));
    }
    builder.verification(buildImpactStep());

    const chain = builder.build();

    // Enforce the charter confidence cap.
    if (chain.confidence > T.confidence_cap) {
      chain.confidence_factors.push({
        factor: "g4_structural_cap",
        adjustment: T.confidence_cap - chain.confidence,
        rationale:
          `G4 charter caps confidence at ${T.confidence_cap} — structural ` +
          `signals are strong but not definitive proof of malicious intent.`,
      });
      chain.confidence = T.confidence_cap;
    }

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

function addSignalFactors(
  builder: EvidenceChainBuilder,
  site: SiteSignals,
): void {
  // Base factor describing the signal fan-out.
  builder.factor(
    "description_length",
    T.base_confidence -
      0.30 + // re-express vs computeConfidence base (0.70 for full chain).
      Math.min(0.10, site.description_length / 100_000),
    `Description length ${site.description_length} bytes ` +
      `(${site.parameter_count} params → ${site.description_parameter_ratio.toFixed(0)} bytes/param).`,
  );

  // Peer z-score factor — always reported, positive adjustment only when
  // the signal actually fires, so a below-threshold z-score contributes
  // zero.
  const zFactorValue = signalsContains(site.signals, "peer_zscore_outlier")
    ? T.factor_increment
    : 0;
  const zRationale =
    site.peer_zscore === null
      ? `Peer sample too small (${site.peer_sample_size} tools; need ≥ ${T.min_peer_sample}) — z-score not computed.`
      : `Peer z-score ${site.peer_zscore.toFixed(2)} across ${site.peer_sample_size} sibling tools ` +
        `(threshold ${T.zscore_threshold}).`;
  builder.factor("peer_relative_zscore", zFactorValue, zRationale);

  // Tail-imperative density factor.
  const tailFactorValue = signalsContains(site.signals, "tail_imperative_density")
    ? T.factor_increment
    : 0;
  builder.factor(
    "tail_phrase_signal",
    tailFactorValue,
    `Tail weighted-imperative hits: ${site.tail_imperative_hits} ` +
      `(threshold ${T.tail_imperative_threshold}) over the last ` +
      `${Math.round(T.tail_fraction * 100)}% of the description.`,
  );

  // Repetition factor.
  if (signalsContains(site.signals, "repetitive_padding")) {
    builder.factor(
      "unique_line_ratio_below_threshold",
      T.factor_increment,
      `Unique-line ratio ${site.unique_line_ratio.toFixed(3)} ` +
        `(threshold ${T.unique_line_min_ratio}) over ${site.description_length} bytes ` +
        `— deliberate repetition signature.`,
    );
  }

  // Ratio factor.
  if (signalsContains(site.signals, "description_parameter_ratio")) {
    builder.factor(
      "description_parameter_ratio_exceeded",
      T.factor_increment,
      `Description-to-parameter ratio ${site.description_parameter_ratio.toFixed(0)} ` +
        `bytes/param (threshold ${T.ratio_threshold}).`,
    );
  }

  // Signal-count bonus — multi-factor hits are meaningfully stronger.
  if (site.signals.length >= 3) {
    builder.factor(
      "multi_signal_convergence",
      0.05,
      `${site.signals.length} independent saturation signals converged — ` +
        `single-signal false positives are far more likely than three co-firing signals.`,
    );
  }
}

function signalsContains(
  signals: readonly SaturationSignal[],
  target: SaturationSignal,
): boolean {
  for (const s of signals) if (s === target) return true;
  return false;
}

registerTypedRuleV2(new G4Rule());

export { G4Rule };
