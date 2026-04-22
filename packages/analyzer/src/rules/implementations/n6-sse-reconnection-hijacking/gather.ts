import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  RISK_FRAGMENTS,
  AUTH_FRAGMENTS,
  N6_AUTH_WINDOW,
  type RiskFragment,
} from "./data/sse-surfaces.js";

export interface ReconnectSite {
  location: Location;
  line: number;
  line_text: string;
  fragment: RiskFragment;
  auth_distance: number | null;
  auth_label: string | null;
}

export interface N6Gathered {
  sites: ReconnectSite[];
  /** True when the source mentions Streamable HTTP / SSE anywhere. Gate. */
  transport_present: boolean;
}

function findAuthNearby(
  lines: string[],
  idx: number,
): { label: string; distance: number } | null {
  const lo = Math.max(0, idx - N6_AUTH_WINDOW);
  const hi = Math.min(lines.length - 1, idx + N6_AUTH_WINDOW);
  let best: { label: string; distance: number } | null = null;
  for (let i = lo; i <= hi; i++) {
    const lc = lines[i].toLowerCase();
    for (const [frag, label] of Object.entries(AUTH_FRAGMENTS)) {
      if (lc.indexOf(frag) !== -1) {
        const d = Math.abs(i - idx);
        if (!best || d < best.distance) best = { distance: d, label };
      }
    }
  }
  return best;
}

export function gatherN6(context: AnalysisContext): N6Gathered {
  const source = context.source_code;
  if (!source) return { sites: [], transport_present: false };
  const lcSrc = source.toLowerCase();
  if (lcSrc.indexOf("__tests__") !== -1 || lcSrc.indexOf(".test.") !== -1)
    return { sites: [], transport_present: false };

  // Honest-refusal gate: skip if no Streamable HTTP / SSE transport hint in
  // the file. SSE reconnection only matters when SSE is in use.
  const transportPresent =
    lcSrc.indexOf("eventsource") !== -1 ||
    lcSrc.indexOf("text/event-stream") !== -1 ||
    lcSrc.indexOf("last-event-id") !== -1 ||
    lcSrc.indexOf("streamable") !== -1;
  if (!transportPresent) return { sites: [], transport_present: false };

  const lines = source.split("\n");
  const sites: ReconnectSite[] = [];
  const fragKeys = Object.keys(RISK_FRAGMENTS);
  for (let i = 0; i < lines.length; i++) {
    const lc = lines[i].toLowerCase();
    let hit: RiskFragment | null = null;
    for (const k of fragKeys) {
      if (lc.indexOf(k) !== -1) {
        hit = RISK_FRAGMENTS[k];
        break;
      }
    }
    if (!hit) continue;
    const auth = findAuthNearby(lines, i);
    sites.push({
      location: { kind: "source", file: "<aggregated>", line: i + 1 },
      line: i + 1,
      line_text: lines[i].trim().slice(0, 160),
      fragment: hit,
      auth_distance: auth?.distance ?? null,
      auth_label: auth?.label ?? null,
    });
  }
  return { sites, transport_present: true };
}
