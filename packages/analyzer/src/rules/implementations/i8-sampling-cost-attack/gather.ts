/**
 * I8 gather — detect sampling capability declared AND absence of any
 * cost-control vocabulary in source code.
 */

import type { AnalysisContext } from "../../../engine.js";
import { COST_CONTROL_TOKENS, type CostControlToken } from "./data/config.js";

export interface I8Fact {
  sampling_declared: boolean;
  source_available: boolean;
  observed_controls: CostControlToken[];
  has_sampling_handler: boolean;
}

export interface I8GatherResult {
  fact: I8Fact | null;
}

export function gatherI8(context: AnalysisContext): I8GatherResult {
  if (!context.declared_capabilities?.sampling) return { fact: null };

  const src = context.source_code ?? "";
  const hasSrc = src.length > 0;
  const observed: CostControlToken[] = [];

  if (hasSrc) {
    for (const entry of Object.values(COST_CONTROL_TOKENS)) {
      if (src.includes(entry.token)) observed.push(entry);
    }
  }

  const hasSamplingHandler = hasSrc
    ? src.includes("sampling/create") ||
      src.includes("handleSampling") ||
      src.includes("createSample")
    : false;

  // Only fire when sampling declared AND either:
  //   - source present AND no controls, OR
  //   - source missing (informational — cannot verify)
  if (hasSrc && observed.length > 0) return { fact: null };

  return {
    fact: {
      sampling_declared: true,
      source_available: hasSrc,
      observed_controls: observed,
      has_sampling_handler: hasSamplingHandler,
    },
  };
}
