import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";

export interface B6Site {
  tool_name: string;
  variant: "explicit-true" | "unset-default-true";
}

export function gatherB6(context: AnalysisContext): B6Site[] {
  const out: B6Site[] = [];
  for (const tool of context.tools ?? []) {
    const schema = tool.input_schema;
    if (!schema) continue;
    if (!schema.properties) continue; // B4 owns the no-properties case

    const addl = schema.additionalProperties;
    if (addl === true) {
      out.push({ tool_name: tool.name, variant: "explicit-true" });
    } else if (addl === undefined) {
      out.push({ tool_name: tool.name, variant: "unset-default-true" });
    }
  }
  return out;
}

export function toolLocation(tool_name: string): Location {
  return { kind: "tool", tool_name };
}
