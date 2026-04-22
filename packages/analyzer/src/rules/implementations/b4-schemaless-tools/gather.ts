import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";

export interface SchemalessSite {
  tool_name: string;
  description_length: number;
}

export function gatherB4(context: AnalysisContext): SchemalessSite[] {
  const out: SchemalessSite[] = [];
  for (const tool of context.tools ?? []) {
    if (tool.input_schema === null || tool.input_schema === undefined) {
      out.push({ tool_name: tool.name, description_length: (tool.description ?? "").length });
    }
  }
  return out;
}

export function toolLocation(tool_name: string): Location {
  return { kind: "tool", tool_name };
}
