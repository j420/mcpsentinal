import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  USER_INPUT_SOURCES,
  ERROR_SURFACES,
  SANITISER_FRAGMENTS,
  N4_SANITISER_WINDOW,
  type UserInputSource,
  type ErrorSurface,
} from "./data/error-surfaces.js";

export interface InjectSite {
  location: Location;
  line: number;
  line_text: string;
  user_source: UserInputSource;
  error_surface: ErrorSurface;
  sanitiser_distance: number | null;
  sanitiser_label: string | null;
}

export interface N4Gathered {
  sites: InjectSite[];
}

function nearbySanitiser(
  lines: string[],
  idx: number,
): { distance: number; label: string } | null {
  const lo = Math.max(0, idx - N4_SANITISER_WINDOW);
  const hi = Math.min(lines.length - 1, idx + N4_SANITISER_WINDOW);
  let best: { distance: number; label: string } | null = null;
  for (let i = lo; i <= hi; i++) {
    const lc = lines[i].toLowerCase();
    for (const [frag, label] of Object.entries(SANITISER_FRAGMENTS)) {
      if (lc.indexOf(frag) !== -1) {
        const d = Math.abs(i - idx);
        if (!best || d < best.distance) best = { distance: d, label };
      }
    }
  }
  return best;
}

export function gatherN4(context: AnalysisContext): N4Gathered {
  const source = context.source_code;
  if (!source) return { sites: [] };
  const lcSrc = source.toLowerCase();
  if (lcSrc.indexOf("__tests__") !== -1 || lcSrc.indexOf(".test.") !== -1)
    return { sites: [] };

  const lines = source.split("\n");
  const sites: InjectSite[] = [];
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const lc = raw.toLowerCase();

    // Must contain both a user-input fragment AND an error-surface fragment
    // to qualify as a flow from user input into the error surface.
    let userHit: UserInputSource | null = null;
    for (const [k, v] of Object.entries(USER_INPUT_SOURCES)) {
      if (lc.indexOf(k) !== -1) {
        userHit = v;
        break;
      }
    }
    if (!userHit) continue;

    let errHit: ErrorSurface | null = null;
    for (const [k, v] of Object.entries(ERROR_SURFACES)) {
      if (lc.indexOf(k) !== -1) {
        errHit = v;
        break;
      }
    }
    if (!errHit) continue;

    const san = nearbySanitiser(lines, i);
    sites.push({
      location: { kind: "source", file: "<aggregated>", line: i + 1 },
      line: i + 1,
      line_text: raw.trim().slice(0, 160),
      user_source: userHit,
      error_surface: errHit,
      sanitiser_distance: san?.distance ?? null,
      sanitiser_label: san?.label ?? null,
    });
  }
  return { sites };
}
