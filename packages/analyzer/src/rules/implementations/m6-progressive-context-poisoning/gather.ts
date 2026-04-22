/**
 * M6 gather — line-level structural scan for accumulation-without-bounds.
 *
 * Deterministic. No regex literals. Works on `context.source_code`
 * (concatenated). Produces one AccumulationSite per candidate line; the
 * caller decides whether to emit findings.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  ACCUMULATION_VERBS,
  CONTEXT_IDENT_FRAGMENTS,
  BOUND_KEYWORDS,
  VECTOR_STORE_FRAGMENTS,
  M6_BOUND_WINDOW_LINES,
  type AccumulationVerb,
} from "./data/accumulation-surfaces.js";

export interface AccumulationSite {
  location: Location; // kind: "source"
  line: number;
  line_text: string;
  verb: AccumulationVerb;
  context_fragment: string;
  context_label: string;
  /** True when the line ALSO mentions a vector-store fragment. */
  vector_store_context: boolean;
  /**
   * Distance in lines to the nearest bound keyword, window-bounded. null
   * when no bound keyword found within M6_BOUND_WINDOW_LINES lines.
   */
  bound_distance: number | null;
  /** Label of the nearest bound keyword, when present. */
  bound_label: string | null;
}

export interface M6Gathered {
  sites: AccumulationSite[];
}

function isTestLikePath(source: string): boolean {
  const lc = source.toLowerCase();
  // A test header near the start, or common test-file markers embedded.
  return (
    lc.indexOf("__tests__") !== -1 ||
    lc.indexOf("__test__") !== -1 ||
    lc.indexOf(".test.") !== -1 ||
    lc.indexOf(".spec.") !== -1 ||
    lc.indexOf("describe(") !== -1 && lc.indexOf("expect(") !== -1
  );
}

function lineContains(lineLc: string, fragments: ReadonlyArray<string>): string | null {
  for (const f of fragments) {
    if (lineLc.indexOf(f) !== -1) return f;
  }
  return null;
}

function findNearestBound(
  lines: string[],
  lineIdx: number,
): { distance: number; label: string } | null {
  const lo = Math.max(0, lineIdx - M6_BOUND_WINDOW_LINES);
  const hi = Math.min(lines.length - 1, lineIdx + M6_BOUND_WINDOW_LINES);
  let best: { distance: number; label: string } | null = null;
  for (let i = lo; i <= hi; i++) {
    const lc = lines[i].toLowerCase();
    for (const [kw, label] of Object.entries(BOUND_KEYWORDS)) {
      if (lc.indexOf(kw) !== -1) {
        const dist = Math.abs(i - lineIdx);
        if (!best || dist < best.distance) best = { distance: dist, label };
      }
    }
  }
  return best;
}

export function gatherM6(context: AnalysisContext): M6Gathered {
  const source = context.source_code;
  if (!source) return { sites: [] };
  if (isTestLikePath(source)) return { sites: [] };

  const lines = source.split("\n");
  if (lines.length < 50) return { sites: [] };

  const verbKeys = Object.keys(ACCUMULATION_VERBS);
  const vectorKeys = Object.keys(VECTOR_STORE_FRAGMENTS);
  const contextKeys = Object.keys(CONTEXT_IDENT_FRAGMENTS);

  const sites: AccumulationSite[] = [];
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    if (raw.length === 0) continue;
    const lc = raw.toLowerCase();

    // Line must contain an accumulation verb AND a context-shaped
    // identifier fragment. Both checks are `indexOf` — byte-level, no
    // regex.
    let hitVerb: AccumulationVerb | null = null;
    for (const vk of verbKeys) {
      if (lc.indexOf(vk) !== -1) {
        hitVerb = ACCUMULATION_VERBS[vk];
        break;
      }
    }
    if (!hitVerb) continue;

    const ctxFrag = lineContains(lc, contextKeys);
    if (!ctxFrag) continue;
    const ctxLabel = CONTEXT_IDENT_FRAGMENTS[ctxFrag];

    const bound = findNearestBound(lines, i);
    const vectorFrag = lineContains(lc, vectorKeys);

    const location: Location = {
      kind: "source",
      file: "<aggregated>",
      line: i + 1,
    };

    sites.push({
      location,
      line: i + 1,
      line_text: raw.trim().slice(0, 160),
      verb: hitVerb,
      context_fragment: ctxFrag,
      context_label: ctxLabel,
      vector_store_context: vectorFrag !== null,
      bound_distance: bound?.distance ?? null,
      bound_label: bound?.label ?? null,
    });
  }

  return { sites };
}
