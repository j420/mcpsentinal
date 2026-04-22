import type { AnalysisContext } from "../../../engine.js";
import {
  J5_RESPONSE_PATTERNS,
  type ResponseManipulationSpec,
} from "./data/config.js";

export interface J5Hit {
  spec_key: string;
  spec: ResponseManipulationSpec;
  line_number: number;
  line_preview: string;
}

export interface J5GatherResult {
  hits: J5Hit[];
}

export function gatherJ5(context: AnalysisContext): J5GatherResult {
  const hits: J5Hit[] = [];
  const src = context.source_code ?? "";
  if (!src) return { hits };
  const lines = src.split("\n");

  for (const [key, spec] of Object.entries(J5_RESPONSE_PATTERNS)) {
    const rt = spec.response_token.toLowerCase();
    const it = spec.instruction_token.toLowerCase();
    const tt = spec.target_token.toLowerCase();
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].toLowerCase();
      if (line.includes(rt) && line.includes(it) && line.includes(tt)) {
        hits.push({
          spec_key: key,
          spec,
          line_number: i + 1,
          line_preview: lines[i].trim().slice(0, 160),
        });
        break;
      }
    }
  }
  return { hits };
}
