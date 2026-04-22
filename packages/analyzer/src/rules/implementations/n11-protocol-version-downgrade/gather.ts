import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  VERSION_ECHO_FRAGMENTS,
  ENFORCEMENT_FRAGMENTS,
} from "./data/n11-config.js";

export interface DowngradeSite {
  location: Location;
  line: number;
  line_text: string;
  echo_label: string;
  enforcement_present: boolean;
  enforcement_distance: number | null;
  enforcement_label: string | null;
}

export interface N11Gathered {
  sites: DowngradeSite[];
}

const WINDOW = 8;

function findEnforcement(
  lines: string[],
  idx: number,
): { label: string; distance: number } | null {
  const lo = Math.max(0, idx - WINDOW);
  const hi = Math.min(lines.length - 1, idx + WINDOW);
  let best: { label: string; distance: number } | null = null;
  for (let i = lo; i <= hi; i++) {
    const lc = lines[i].toLowerCase();
    for (const [k, label] of Object.entries(ENFORCEMENT_FRAGMENTS)) {
      if (lc.indexOf(k) !== -1) {
        const d = Math.abs(i - idx);
        if (!best || d < best.distance) best = { label, distance: d };
      }
    }
  }
  return best;
}

export function gatherN11(context: AnalysisContext): N11Gathered {
  const source = context.source_code;
  if (!source) return { sites: [] };
  const lcSrc = source.toLowerCase();
  if (lcSrc.indexOf("__tests__") !== -1 || lcSrc.indexOf(".test.") !== -1)
    return { sites: [] };

  const lines = source.split("\n");
  const sites: DowngradeSite[] = [];
  for (let i = 0; i < lines.length; i++) {
    const lc = lines[i].toLowerCase();
    let echoLabel: string | null = null;
    for (const [k, label] of Object.entries(VERSION_ECHO_FRAGMENTS)) {
      if (lc.indexOf(k) !== -1) {
        echoLabel = label;
        break;
      }
    }
    if (!echoLabel) continue;
    const enforcement = findEnforcement(lines, i);
    sites.push({
      location: { kind: "source", file: "<aggregated>", line: i + 1 },
      line: i + 1,
      line_text: lines[i].trim().slice(0, 160),
      echo_label: echoLabel,
      enforcement_present: enforcement !== null,
      enforcement_distance: enforcement?.distance ?? null,
      enforcement_label: enforcement?.label ?? null,
    });
  }
  return { sites };
}
