/**
 * G4 — Context Window Saturation: named VerificationStep factories.
 *
 * Every step returns a VerificationStep whose `target` is a structured
 * Location (not a prose string). The steps are meant to be actionable
 * by a human reviewer: each one names a specific tool, a concrete
 * measurement, and an expected observation.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { SiteSignals } from "./gather.js";
import { CONTEXT_SATURATION_THRESHOLDS as T } from "./data/context-saturation-thresholds.js";

function toolLoc(tool_name: string): Location {
  return { kind: "tool", tool_name };
}

function attentionLoc(): Location {
  return { kind: "capability", capability: "tools" };
}

export function buildLongDescriptionSourceStep(
  site: SiteSignals,
): VerificationStep {
  return {
    step_type: "inspect-description",
    instruction:
      `Measure the description length of tool "${site.tool_name}" and ` +
      `compare it to ${T.min_description_length} (absolute floor for G4 ` +
      `analysis) and ${T.high_suspicion_length} (high-suspicion absolute ` +
      `threshold). Then count declared input parameters and compute the ` +
      `bytes-per-parameter ratio — legitimate tools stay below ~150.`,
    target: toolLoc(site.tool_name),
    expected_observation:
      `Description is ${site.description_length} bytes for ` +
      `${site.parameter_count} parameter(s) — ratio ` +
      `${site.description_parameter_ratio.toFixed(0)} bytes/param ` +
      `(G4 flags ≥ ${T.ratio_threshold} with length ≥ ${T.high_suspicion_length}).`,
  };
}

export function buildPeerZscoreStep(site: SiteSignals): VerificationStep {
  const zText =
    site.peer_zscore === null
      ? `peer sample too small (${site.peer_sample_size} tools; need ≥ ${T.min_peer_sample})`
      : `${site.peer_zscore.toFixed(2)}σ above peer mean`;
  return {
    step_type: "compare-baseline",
    instruction:
      `Across every tool in this server, compute the per-server mean and ` +
      `standard deviation of description lengths. Place tool ` +
      `"${site.tool_name}" on that distribution — a z-score at or above ` +
      `${T.zscore_threshold} indicates the description is a statistical ` +
      `outlier relative to its own siblings.`,
    target: toolLoc(site.tool_name),
    expected_observation:
      `Length ${site.description_length} bytes across ${site.peer_sample_size} ` +
      `sibling tools places "${site.tool_name}" at ${zText}.`,
  };
}

export function buildTailPayloadStep(site: SiteSignals): VerificationStep {
  const hitSummary =
    site.tail_hits.length === 0
      ? "no imperative-verb hits"
      : site.tail_hits
          .map((h) => `${h.verb}@${h.offset}(w${h.weight})`)
          .slice(0, 8)
          .join(", ");
  return {
    step_type: "inspect-description",
    instruction:
      `Read only the last ${Math.round(T.tail_fraction * 100)}% of tool ` +
      `"${site.tool_name}"'s description (bytes ${site.tail_offset} to ` +
      `${site.description_length}). Because LLMs exhibit recency bias, ` +
      `imperative verbs concentrated in this tail region are high-signal ` +
      `indicators of a payload positioned to maximise attention weight.`,
    target: toolLoc(site.tool_name),
    expected_observation:
      `Tail segment carries ${site.tail_imperative_hits} weighted imperative ` +
      `hits (threshold ${T.tail_imperative_threshold}): ${hitSummary}.`,
  };
}

export function buildRepetitionStep(site: SiteSignals): VerificationStep {
  return {
    step_type: "inspect-description",
    instruction:
      `Split the description of tool "${site.tool_name}" on newlines and ` +
      `compute the unique-line ratio (distinct lines / non-empty lines). ` +
      `A ratio below ${T.unique_line_min_ratio} over a ≥${T.unique_line_min_length}-` +
      `byte description is deliberate repetition — legitimate documentation ` +
      `stays well above 0.5.`,
    target: toolLoc(site.tool_name),
    expected_observation:
      `Unique-line ratio is ${site.unique_line_ratio.toFixed(3)} across ` +
      `${site.description_length} bytes ` +
      `(G4 flags < ${T.unique_line_min_ratio}).`,
  };
}

export function buildImpactStep(): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Review how the MCP client delivers the tool catalogue to the model. ` +
      `If the entire tool-description corpus is concatenated into the ` +
      `system/context block before user messages, oversized descriptions ` +
      `directly displace earlier safety instructions from the effective ` +
      `attention window. Enforce a per-tool description length cap ` +
      `(e.g. ≤500 bytes) in the client or gateway.`,
    target: attentionLoc(),
    expected_observation:
      `No client-side length cap is enforced; tool descriptions of any ` +
      `length are fed verbatim into the model's context.`,
  };
}
