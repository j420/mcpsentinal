import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import { STRING_CONSTRAINTS, NUMBER_CONSTRAINTS } from "./data/constraint-keywords.js";

export interface UnconstrainedSite {
  tool_name: string;
  unconstrained: Array<{ param: string; type: string }>;
  total_params: number;
}

function hasStringConstraint(prop: Record<string, unknown>): boolean {
  for (const key of Object.keys(STRING_CONSTRAINTS)) {
    if (prop[key] !== undefined) return true;
  }
  return false;
}

function hasNumberConstraint(prop: Record<string, unknown>): boolean {
  for (const key of Object.keys(NUMBER_CONSTRAINTS)) {
    if (prop[key] !== undefined) return true;
  }
  return false;
}

export function gatherB1(context: AnalysisContext): UnconstrainedSite[] {
  const out: UnconstrainedSite[] = [];
  for (const tool of context.tools ?? []) {
    const schema = tool.input_schema;
    if (!schema) continue;
    const props = (schema.properties ?? null) as Record<string, Record<string, unknown>> | null;
    if (!props) continue;
    const entries = Object.entries(props);
    const unconstrained: Array<{ param: string; type: string }> = [];
    for (const [name, prop] of entries) {
      if (prop.type === "string" && !hasStringConstraint(prop)) {
        unconstrained.push({ param: name, type: "string" });
      } else if (prop.type === "number" && !hasNumberConstraint(prop)) {
        unconstrained.push({ param: name, type: "number" });
      } else if (prop.type === "integer" && !hasNumberConstraint(prop)) {
        unconstrained.push({ param: name, type: "integer" });
      }
    }
    if (unconstrained.length > 0) {
      out.push({ tool_name: tool.name, unconstrained, total_params: entries.length });
    }
  }
  return out;
}

export function toolLocation(tool_name: string): Location {
  return { kind: "tool", tool_name };
}

export function paramLocation(tool_name: string, param: string): Location {
  return { kind: "parameter", tool_name, parameter_path: `input_schema.properties.${param}` };
}
