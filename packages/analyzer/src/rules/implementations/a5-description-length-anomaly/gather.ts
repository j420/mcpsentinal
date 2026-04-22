import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import { LENGTH_THRESHOLDS } from "./data/thresholds.js";

export interface LengthSite {
  tool_name: string;
  length: number;
  /** Raw confidence from length only (pre-cap). */
  raw_confidence: number;
}

export function gatherA5(context: AnalysisContext): LengthSite[] {
  const out: LengthSite[] = [];
  for (const tool of context.tools ?? []) {
    const desc = tool.description ?? "";
    if (desc.length < LENGTH_THRESHOLDS.minimum_length) continue;
    const over = desc.length - LENGTH_THRESHOLDS.minimum_length;
    const raw =
      LENGTH_THRESHOLDS.base_confidence +
      (over / 1000) * LENGTH_THRESHOLDS.confidence_scale_per_kchar;
    out.push({
      tool_name: tool.name,
      length: desc.length,
      raw_confidence: Math.min(LENGTH_THRESHOLDS.confidence_cap, raw),
    });
  }
  return out;
}

export function toolLocation(tool_name: string): Location {
  return { kind: "tool", tool_name };
}
