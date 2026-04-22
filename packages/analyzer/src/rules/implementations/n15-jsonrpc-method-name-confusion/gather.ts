import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import { damerauLevenshtein } from "../../analyzers/similarity.js";
import { allSpecMethods, isSpecMethod } from "../_shared/mcp-method-catalogue.js";
import {
  USER_DISPATCH_FRAGMENTS,
  REGISTRATION_FRAGMENTS,
  N15_LEVENSHTEIN_MAX_DISTANCE,
} from "./data/n15-config.js";

export type ConfusionType =
  | "user_input_dispatch"
  | "near_canonical_method"
  | "dynamic_property_access"
  | "unicode_homoglyph";

export interface ConfusionSite {
  location: Location;
  line: number;
  line_text: string;
  type: ConfusionType;
  label: string;
  /** Populated for near_canonical_method — the closest canonical name. */
  nearest_canonical: string | null;
  /** Populated for near_canonical_method — edit distance to nearest. */
  levenshtein_distance: number | null;
  /** Populated for all types — the observed method name string (if any). */
  observed_name: string | null;
}

export interface N15Gathered {
  sites: ConfusionSite[];
}

/** Extract a string literal from a handler-registration-shaped line, if any. */
function extractRegistrationName(line: string): string | null {
  // naïve: find first quoted substring on the line. Avoids regex.
  const indicators = ["'", '"', "`"];
  for (const q of indicators) {
    const start = line.indexOf(q);
    if (start === -1) continue;
    const end = line.indexOf(q, start + 1);
    if (end === -1) continue;
    return line.slice(start + 1, end);
  }
  return null;
}

function containsNonAscii(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const cp = s.charCodeAt(i);
    if (cp > 127) return true;
  }
  return false;
}

export function gatherN15(context: AnalysisContext): N15Gathered {
  const source = context.source_code;
  if (!source) return { sites: [] };
  const lcSrc = source.toLowerCase();
  if (lcSrc.indexOf("__tests__") !== -1 || lcSrc.indexOf(".test.") !== -1)
    return { sites: [] };

  const lines = source.split("\n");
  const sites: ConfusionSite[] = [];
  const specMethods = allSpecMethods();

  for (let i = 0; i < lines.length; i++) {
    const lc = lines[i].toLowerCase();

    // (1) user-input-as-method-name
    for (const [k, label] of Object.entries(USER_DISPATCH_FRAGMENTS)) {
      if (lc.indexOf(k) !== -1) {
        sites.push({
          location: { kind: "source", file: "<aggregated>", line: i + 1 },
          line: i + 1,
          line_text: lines[i].trim().slice(0, 160),
          type: "user_input_dispatch",
          label,
          nearest_canonical: null,
          levenshtein_distance: null,
          observed_name: null,
        });
        break;
      }
    }

    // (2) handler registration → check canonical-closeness / homoglyph
    let hadRegistration = false;
    for (const k of Object.keys(REGISTRATION_FRAGMENTS)) {
      if (lc.indexOf(k) !== -1) {
        hadRegistration = true;
        break;
      }
    }
    if (hadRegistration) {
      const observed = extractRegistrationName(lines[i]);
      if (observed) {
        const obsLc = observed.toLowerCase();
        if (!isSpecMethod(observed) && !isSpecMethod(obsLc)) {
          // Unicode homoglyph variant?
          if (containsNonAscii(observed)) {
            sites.push({
              location: { kind: "source", file: "<aggregated>", line: i + 1 },
              line: i + 1,
              line_text: lines[i].trim().slice(0, 160),
              type: "unicode_homoglyph",
              label: `non-ASCII characters in method name "${observed}"`,
              nearest_canonical: null,
              levenshtein_distance: null,
              observed_name: observed,
            });
          } else {
            // Compute Levenshtein distance to closest canonical method
            let best: { name: string; dist: number } | null = null;
            for (const m of specMethods) {
              const d = damerauLevenshtein(obsLc, m.toLowerCase());
              if (!best || d < best.dist) best = { name: m, dist: d };
            }
            if (best && best.dist > 0 && best.dist <= N15_LEVENSHTEIN_MAX_DISTANCE) {
              sites.push({
                location: { kind: "source", file: "<aggregated>", line: i + 1 },
                line: i + 1,
                line_text: lines[i].trim().slice(0, 160),
                type: "near_canonical_method",
                label: `handler name "${observed}" is ${best.dist} edit(s) from canonical "${best.name}"`,
                nearest_canonical: best.name,
                levenshtein_distance: best.dist,
                observed_name: observed,
              });
            }
          }
        }
      }
    }

    // (3) dynamic property access on a known-safe surface
    if (
      (lc.indexOf("server[req.method]") !== -1 ||
        lc.indexOf("handlers[req.method]") !== -1) &&
      lc.indexOf("(") !== -1
    ) {
      sites.push({
        location: { kind: "source", file: "<aggregated>", line: i + 1 },
        line: i + 1,
        line_text: lines[i].trim().slice(0, 160),
        type: "dynamic_property_access",
        label: "dynamic property-access dispatch via user-controlled method",
        nearest_canonical: null,
        levenshtein_distance: null,
        observed_name: null,
      });
    }
  }

  return { sites };
}
