import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  UPDATE_EMIT_FRAGMENTS,
  INTEGRITY_FRAGMENTS,
  SUBSCRIBE_FRAGMENTS,
} from "./data/n12-config.js";

export interface UpdateSite {
  location: Location;
  line: number;
  line_text: string;
  emit_label: string;
  integrity_present: boolean;
  integrity_distance: number | null;
  integrity_label: string | null;
}

export interface N12Gathered {
  sites: UpdateSite[];
  subscription_surface_present: boolean;
}

const WINDOW = 6;

function findIntegrity(
  lines: string[],
  idx: number,
): { label: string; distance: number } | null {
  const lo = Math.max(0, idx - WINDOW);
  const hi = Math.min(lines.length - 1, idx + WINDOW);
  let best: { label: string; distance: number } | null = null;
  for (let i = lo; i <= hi; i++) {
    const lc = lines[i].toLowerCase();
    for (const [k, label] of Object.entries(INTEGRITY_FRAGMENTS)) {
      if (lc.indexOf(k) !== -1) {
        const d = Math.abs(i - idx);
        if (!best || d < best.distance) best = { label, distance: d };
      }
    }
  }
  return best;
}

export function gatherN12(context: AnalysisContext): N12Gathered {
  const source = context.source_code;
  if (!source) return { sites: [], subscription_surface_present: false };
  const lcSrc = source.toLowerCase();
  if (lcSrc.indexOf("__tests__") !== -1 || lcSrc.indexOf(".test.") !== -1)
    return { sites: [], subscription_surface_present: false };

  // Honest-refusal gate.
  let subscribePresent = false;
  for (const k of Object.keys(SUBSCRIBE_FRAGMENTS)) {
    if (lcSrc.indexOf(k) !== -1) {
      subscribePresent = true;
      break;
    }
  }
  if (!subscribePresent) return { sites: [], subscription_surface_present: false };

  const lines = source.split("\n");
  const sites: UpdateSite[] = [];
  const emitKeys = Object.keys(UPDATE_EMIT_FRAGMENTS);
  for (let i = 0; i < lines.length; i++) {
    const lc = lines[i].toLowerCase();
    let emitLabel: string | null = null;
    for (const k of emitKeys) {
      if (lc.indexOf(k) !== -1) {
        emitLabel = UPDATE_EMIT_FRAGMENTS[k];
        break;
      }
    }
    if (!emitLabel) continue;
    const integ = findIntegrity(lines, i);
    sites.push({
      location: { kind: "source", file: "<aggregated>", line: i + 1 },
      line: i + 1,
      line_text: lines[i].trim().slice(0, 160),
      emit_label: emitLabel,
      integrity_present: integ !== null,
      integrity_distance: integ?.distance ?? null,
      integrity_label: integ?.label ?? null,
    });
  }
  return { sites, subscription_surface_present: true };
}
