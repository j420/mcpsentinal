import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import { DANGEROUS_PARAM_NAMES, type DangerousSink } from "./data/dangerous-names.js";

export interface DangerousSite {
  tool_name: string;
  params: Array<{ name: string; sink: DangerousSink; rationale: string }>;
}

function normaliseName(s: string): string {
  let out = "";
  for (let i = 0; i < s.length; i++) {
    const cp = s.charCodeAt(i);
    if (cp >= 0x41 && cp <= 0x5a) out += String.fromCharCode(cp + 32);
    else if ((cp >= 0x30 && cp <= 0x39) || (cp >= 0x61 && cp <= 0x7a) || cp === 0x5f) out += s[i];
    else if (cp === 0x2d) out += "_";
  }
  return out;
}

export function gatherB2(context: AnalysisContext): DangerousSite[] {
  const out: DangerousSite[] = [];
  for (const tool of context.tools ?? []) {
    const schema = tool.input_schema;
    if (!schema) continue;
    const props = (schema.properties ?? null) as Record<string, unknown> | null;
    if (!props) continue;
    const params: Array<{ name: string; sink: DangerousSink; rationale: string }> = [];
    for (const name of Object.keys(props)) {
      const norm = normaliseName(name);
      const entry = DANGEROUS_PARAM_NAMES[norm];
      if (entry) params.push({ name, sink: entry.sink, rationale: entry.rationale });
    }
    if (params.length > 0) out.push({ tool_name: tool.name, params });
  }
  return out;
}

export function toolLocation(tool_name: string): Location {
  return { kind: "tool", tool_name };
}
