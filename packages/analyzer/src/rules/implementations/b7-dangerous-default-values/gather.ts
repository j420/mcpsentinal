import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  DESTRUCTIVE_BOOL_PARAMS,
  READ_ONLY_FLAG_NAMES,
  DANGEROUS_STRING_DEFAULTS,
  PATH_PARAM_TOKENS,
} from "./data/dangerous-defaults.js";

export interface B7Site {
  tool_name: string;
  parameter_name: string;
  label: string;
  rationale: string;
  default_value: string;
  category: "destructive-bool" | "read-only-false" | "path-root-default" | "wildcard-default";
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

function paramTokens(s: string): string[] {
  const out: string[] = [];
  let buf = "";
  for (let i = 0; i < s.length; i++) {
    const cp = s.charCodeAt(i);
    const isWord =
      (cp >= 0x30 && cp <= 0x39) ||
      (cp >= 0x41 && cp <= 0x5a) ||
      (cp >= 0x61 && cp <= 0x7a);
    if (isWord) {
      if (cp >= 0x41 && cp <= 0x5a) buf += String.fromCharCode(cp + 32);
      else buf += s[i];
    } else {
      if (buf) out.push(buf);
      buf = "";
    }
  }
  if (buf) out.push(buf);
  return out;
}

export function gatherB7(context: AnalysisContext): B7Site[] {
  const out: B7Site[] = [];
  for (const tool of context.tools ?? []) {
    const props = (tool.input_schema?.properties ?? null) as Record<string, Record<string, unknown>> | null;
    if (!props) continue;
    for (const [paramName, paramDef] of Object.entries(props)) {
      if (paramDef.default === undefined) continue;
      const defaultVal = paramDef.default;
      const defaultStr = String(defaultVal);
      const norm = normaliseName(paramName);

      // Destructive bool defaulting to true
      const destructive = DESTRUCTIVE_BOOL_PARAMS[norm];
      if (destructive && defaultStr.toLowerCase() === "true") {
        out.push({
          tool_name: tool.name,
          parameter_name: paramName,
          label: destructive.label,
          rationale: destructive.rationale,
          default_value: defaultStr,
          category: "destructive-bool",
        });
        continue;
      }

      // read_only: false
      const readOnly = READ_ONLY_FLAG_NAMES[norm];
      if (readOnly && defaultStr.toLowerCase() === "false") {
        out.push({
          tool_name: tool.name,
          parameter_name: paramName,
          label: readOnly.label,
          rationale: readOnly.rationale,
          default_value: defaultStr,
          category: "read-only-false",
        });
        continue;
      }

      // Path parameter defaulting to /, *, **
      const tks = paramTokens(paramName);
      const isPathParam = tks.some((t) => PATH_PARAM_TOKENS.has(t));
      if (isPathParam) {
        for (const spec of DANGEROUS_STRING_DEFAULTS) {
          if (defaultStr === spec.value) {
            out.push({
              tool_name: tool.name,
              parameter_name: paramName,
              label: spec.label,
              rationale: spec.rationale,
              default_value: defaultStr,
              category: spec.value === "/" ? "path-root-default" : "wildcard-default",
            });
            break;
          }
        }
      }
    }
  }
  return out;
}

export function paramLocation(tool_name: string, parameter_name: string): Location {
  return {
    kind: "parameter",
    tool_name,
    parameter_path: `input_schema.properties.${parameter_name}.default`,
  };
}
