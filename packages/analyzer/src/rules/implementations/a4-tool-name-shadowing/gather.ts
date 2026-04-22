/**
 * A4 gather step — name normalisation + Damerau-Levenshtein similarity
 * against the canonical tool-name catalogue.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import { CANONICAL_SET, CANONICAL_TOOLS, type CanonicalName } from "./data/canonical-names.js";
import { damerauLevenshtein } from "../../analyzers/similarity.js";

export interface ShadowSite {
  tool_name: string;
  normalised: string;
  canonical: string;
  canonical_info: CanonicalName;
  distance: number;
  /** "exact" | "fuzzy" — exact after normalisation vs fuzzy ≤ 2 DL */
  kind: "exact" | "fuzzy";
}

export function normalise(name: string): string {
  let out = "";
  for (let i = 0; i < name.length; i++) {
    const cp = name.charCodeAt(i);
    // Collapse dashes, underscores, whitespace → "_"
    if (cp === 0x2d || cp === 0x5f || cp === 0x20) {
      if (out.length > 0 && out[out.length - 1] !== "_") out += "_";
      continue;
    }
    // Lowercase A-Z → a-z
    if (cp >= 0x41 && cp <= 0x5a) {
      out += String.fromCharCode(cp + 32);
      continue;
    }
    out += name[i];
  }
  // Trim trailing underscores
  while (out.endsWith("_")) out = out.slice(0, -1);
  return out;
}

export function gatherA4(context: AnalysisContext): ShadowSite[] {
  const out: ShadowSite[] = [];
  for (const tool of context.tools ?? []) {
    if (!tool.name) continue;
    const normalised = normalise(tool.name);
    if (CANONICAL_SET.has(normalised)) {
      // Exact-after-normalisation
      out.push({
        tool_name: tool.name,
        normalised,
        canonical: normalised,
        canonical_info: CANONICAL_TOOLS[normalised],
        distance: 0,
        kind: "exact",
      });
      continue;
    }
    // Fuzzy — scan every canonical, find minimum DL distance
    let best: { canonical: string; distance: number } | null = null;
    for (const canonical of CANONICAL_SET) {
      const d = damerauLevenshtein(normalised, canonical);
      if (d > 2) continue;
      if (!best || d < best.distance) best = { canonical, distance: d };
    }
    if (best && best.distance > 0 && best.distance <= 2) {
      // Only fire for fuzzy when the name is at least 4 characters
      if (normalised.length >= 4) {
        out.push({
          tool_name: tool.name,
          normalised,
          canonical: best.canonical,
          canonical_info: CANONICAL_TOOLS[best.canonical],
          distance: best.distance,
          kind: "fuzzy",
        });
      }
    }
  }
  return out;
}

export function toolLocation(tool_name: string): Location {
  return { kind: "tool", tool_name };
}
