import type { AnalysisContext } from "../../../engine.js";
import {
  ELICITATION_PHRASES,
  type ElicitationPhraseSpec,
} from "../_shared/protocol-shape-catalogue.js";

export interface I10Hit {
  tool_name: string;
  description_preview: string;
  spec_key: string;
  spec: ElicitationPhraseSpec;
  fence_hit: boolean;
}

export interface I10GatherResult {
  hits: I10Hit[];
}

export function gatherI10(context: AnalysisContext): I10GatherResult {
  const hits: I10Hit[] = [];
  if (!context.tools) return { hits };

  for (const tool of context.tools) {
    const desc = (tool.description ?? "").toLowerCase();
    if (!desc) continue;
    for (const [key, spec] of Object.entries(ELICITATION_PHRASES)) {
      if (spec.kind !== "url-redirect") continue;
      if (!hasAny(desc, spec.leading_tokens)) continue;
      if (!hasAny(desc, spec.target_tokens)) continue;
      const fence = hasAny(desc, spec.false_positive_fence);
      hits.push({
        tool_name: tool.name,
        description_preview: desc.slice(0, 140),
        spec_key: key,
        spec,
        fence_hit: fence,
      });
      break;
    }
  }
  return { hits };
}

function hasAny(haystack: string, tokens: ReadonlyArray<string>): boolean {
  for (const t of tokens) if (haystack.includes(t)) return true;
  return false;
}
