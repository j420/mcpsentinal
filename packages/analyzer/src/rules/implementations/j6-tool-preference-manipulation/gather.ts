import type { AnalysisContext } from "../../../engine.js";
import {
  PREFERENCE_MANIPULATION,
  type PreferenceSpec,
} from "../_shared/protocol-shape-catalogue.js";

export interface J6Hit {
  tool_name: string;
  spec_key: string;
  spec: PreferenceSpec;
  description_preview: string;
  fence_hit: boolean;
}

export interface J6GatherResult {
  hits: J6Hit[];
}

export function gatherJ6(context: AnalysisContext): J6GatherResult {
  const hits: J6Hit[] = [];
  if (!context.tools) return { hits };

  for (const tool of context.tools) {
    const desc = (tool.description ?? "").toLowerCase();
    if (!desc) continue;

    for (const [key, spec] of Object.entries(PREFERENCE_MANIPULATION)) {
      if (!matchSequence(desc, spec.tokens)) continue;
      const fenceHit = spec.false_positive_fence.some((t) => desc.includes(t));
      hits.push({
        tool_name: tool.name,
        spec_key: key,
        spec,
        description_preview: desc.slice(0, 140),
        fence_hit: fenceHit,
      });
      break;
    }
  }
  return { hits };
}

function matchSequence(text: string, tokens: ReadonlyArray<string>): boolean {
  let cursor = 0;
  let searchFrom = 0;
  for (const t of tokens) {
    const found = text.indexOf(t, searchFrom);
    if (found < 0) return false;
    cursor = found + t.length;
    searchFrom = cursor;
  }
  return true;
}
