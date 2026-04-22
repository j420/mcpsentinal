import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  BYPASS_FRAGMENTS,
  TOFU_CONTEXT_FRAGMENTS,
  FIRST_CONNECT_ACCEPT_FRAGMENTS,
} from "./data/n14-config.js";

export type BypassVariant = "pinning_bypass" | "first_connect_accept";

export interface TofuSite {
  location: Location;
  line: number;
  line_text: string;
  variant: BypassVariant;
  fragment_label: string;
}

export interface N14Gathered {
  sites: TofuSite[];
  tofu_context_present: boolean;
}

export function gatherN14(context: AnalysisContext): N14Gathered {
  const source = context.source_code;
  if (!source) return { sites: [], tofu_context_present: false };
  const lcSrc = source.toLowerCase();
  if (lcSrc.indexOf("__tests__") !== -1 || lcSrc.indexOf(".test.") !== -1)
    return { sites: [], tofu_context_present: false };

  // Honest-refusal gate: require TOFU context present somewhere in the source.
  let tofuContext = false;
  for (const k of Object.keys(TOFU_CONTEXT_FRAGMENTS)) {
    if (lcSrc.indexOf(k) !== -1) {
      tofuContext = true;
      break;
    }
  }
  if (!tofuContext) return { sites: [], tofu_context_present: false };

  const lines = source.split("\n");
  const sites: TofuSite[] = [];
  for (let i = 0; i < lines.length; i++) {
    const lc = lines[i].toLowerCase();

    // Pinning bypass
    for (const [k, label] of Object.entries(BYPASS_FRAGMENTS)) {
      if (lc.indexOf(k) !== -1) {
        sites.push({
          location: { kind: "source", file: "<aggregated>", line: i + 1 },
          line: i + 1,
          line_text: lines[i].trim().slice(0, 160),
          variant: "pinning_bypass",
          fragment_label: label,
        });
        break;
      }
    }

    // First-connect accept-any
    for (const [k, label] of Object.entries(FIRST_CONNECT_ACCEPT_FRAGMENTS)) {
      if (lc.indexOf(k) !== -1) {
        sites.push({
          location: { kind: "source", file: "<aggregated>", line: i + 1 },
          line: i + 1,
          line_text: lines[i].trim().slice(0, 160),
          variant: "first_connect_accept",
          fragment_label: label,
        });
        break;
      }
    }
  }

  return { sites, tofu_context_present: true };
}
