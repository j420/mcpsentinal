/**
 * I9 gather — match elicitation-phrased credential harvesting in tool
 * descriptions (leading action token + target token co-occurrence).
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  ELICITATION_PHRASES,
  type ElicitationPhraseSpec,
} from "../_shared/protocol-shape-catalogue.js";

export interface I9Hit {
  tool_name: string;
  description_preview: string;
  spec_key: string;
  spec: ElicitationPhraseSpec;
  fence_hit: boolean;
  weight: number;
}

export interface I9GatherResult {
  hits: I9Hit[];
}

export function gatherI9(context: AnalysisContext): I9GatherResult {
  const hits: I9Hit[] = [];
  if (!context.tools || context.tools.length === 0) return { hits };

  for (const tool of context.tools) {
    const desc = (tool.description ?? "").toLowerCase();
    if (!desc) continue;

    for (const [key, spec] of Object.entries(ELICITATION_PHRASES)) {
      if (spec.kind !== "credential") continue;
      if (!hasAnyToken(desc, spec.leading_tokens)) continue;
      if (!hasAnyToken(desc, spec.target_tokens)) continue;

      const fenceHit = hasAnyToken(desc, spec.false_positive_fence);
      const weight = fenceHit ? spec.weight * 0.5 : spec.weight;

      hits.push({
        tool_name: tool.name,
        description_preview: desc.slice(0, 140),
        spec_key: key,
        spec,
        fence_hit: fenceHit,
        weight,
      });
      break; // one finding per tool
    }
  }
  return { hits };
}

function hasAnyToken(haystack: string, tokens: ReadonlyArray<string>): boolean {
  for (const t of tokens) {
    if (haystack.includes(t)) return true;
  }
  return false;
}
