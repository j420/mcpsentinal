import type { AnalysisContext } from "../../../engine.js";
import {
  SESSION_ANTI_PATTERNS,
  type SessionAntiPatternSpec,
} from "../_shared/protocol-shape-catalogue.js";

export interface I15Hit {
  spec_key: string;
  spec: SessionAntiPatternSpec;
  line_number: number;
  line_preview: string;
}

export interface I15GatherResult {
  hits: I15Hit[];
}

export function gatherI15(context: AnalysisContext): I15GatherResult {
  const hits: I15Hit[] = [];
  const src = context.source_code ?? "";
  if (!src) return { hits };

  // Exclude obvious test files — small heuristic guard without regex.
  const lower = src.toLowerCase();
  if (lower.includes("__tests__") || lower.includes(".test.ts") || lower.includes(".spec.ts")) {
    // test fixtures will often contain intentionally insecure patterns; skip.
    // Only skip when the ENTIRE source bundle is dominated by test markers.
    // We proceed; per-line scan below will still find hits if present.
  }

  const lines = src.split("\n");
  for (const [key, spec] of Object.entries(SESSION_ANTI_PATTERNS)) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].toLowerCase();
      // All trigger tokens must appear in the same line for a positive hit.
      let allPresent = true;
      for (const t of spec.trigger_tokens) {
        if (!line.includes(t)) {
          allPresent = false;
          break;
        }
      }
      if (allPresent) {
        hits.push({
          spec_key: key,
          spec,
          line_number: i + 1,
          line_preview: lines[i].trim().slice(0, 140),
        });
        break; // one per anti-pattern
      }
    }
  }
  return { hits };
}
