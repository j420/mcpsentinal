import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  SMUGGLE_FRAGMENTS,
  TRANSPORT_MARKER_FRAGMENTS,
  SAFE_STACK_MARKERS,
} from "./data/n13-config.js";

export interface SmuggleSite {
  location: Location;
  line: number;
  line_text: string;
  smuggle_label: string;
  dual_headers: boolean;
}

export interface N13Gathered {
  sites: SmuggleSite[];
  transport_present: boolean;
  safe_stack_present: boolean;
}

export function gatherN13(context: AnalysisContext): N13Gathered {
  const source = context.source_code;
  if (!source)
    return { sites: [], transport_present: false, safe_stack_present: false };
  const lcSrc = source.toLowerCase();
  if (lcSrc.indexOf("__tests__") !== -1 || lcSrc.indexOf(".test.") !== -1)
    return { sites: [], transport_present: false, safe_stack_present: false };

  // Honest-refusal: need a Streamable-HTTP / HTTP transport marker
  let transportPresent = false;
  for (const k of Object.keys(TRANSPORT_MARKER_FRAGMENTS)) {
    if (lcSrc.indexOf(k) !== -1) {
      transportPresent = true;
      break;
    }
  }
  if (!transportPresent)
    return { sites: [], transport_present: false, safe_stack_present: false };

  let safeStackPresent = false;
  for (const k of Object.keys(SAFE_STACK_MARKERS)) {
    if (lcSrc.indexOf(k) !== -1) {
      safeStackPresent = true;
      break;
    }
  }

  const lines = source.split("\n");
  const sites: SmuggleSite[] = [];
  // Track whether we saw both transfer-encoding AND content-length in proximity
  let lastTEIdx = -999;

  for (let i = 0; i < lines.length; i++) {
    const lc = lines[i].toLowerCase();
    let hit: string | null = null;
    for (const [k, label] of Object.entries(SMUGGLE_FRAGMENTS)) {
      // For the raw-literal we need the actual backslash-r-n characters in the source
      if (lc.indexOf(k.toLowerCase()) !== -1) {
        hit = label;
        break;
      }
    }
    if (!hit) continue;

    // Flag dual-header shapes: Transfer-Encoding + Content-Length within 3 lines
    const isTE = lc.indexOf("transfer-encoding") !== -1;
    const isCL = lc.indexOf("content-length") !== -1;
    if (isTE) lastTEIdx = i;
    const dual = (isTE && lc.indexOf("content-length") !== -1) ||
      (isCL && i - lastTEIdx <= 3 && i - lastTEIdx >= 0);

    sites.push({
      location: { kind: "source", file: "<aggregated>", line: i + 1 },
      line: i + 1,
      line_text: lines[i].trim().slice(0, 160),
      smuggle_label: hit,
      dual_headers: dual,
    });
  }

  return { sites, transport_present: true, safe_stack_present: safeStackPresent };
}
