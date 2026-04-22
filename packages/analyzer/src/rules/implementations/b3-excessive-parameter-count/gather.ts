import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import { PARAM_COUNT_THRESHOLD } from "./data/thresholds.js";

export interface CountSite {
  tool_name: string;
  count: number;
}

export function gatherB3(context: AnalysisContext): CountSite[] {
  const out: CountSite[] = [];
  for (const tool of context.tools ?? []) {
    const props = (tool.input_schema?.properties ?? null) as Record<string, unknown> | null;
    if (!props) continue;
    const count = Object.keys(props).length;
    if (count > PARAM_COUNT_THRESHOLD) out.push({ tool_name: tool.name, count });
  }
  return out;
}

export function toolLocation(tool_name: string): Location {
  return { kind: "tool", tool_name };
}
