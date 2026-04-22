import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { SchemalessSite } from "./gather.js";

export function stepInspectAbsence(site: SchemalessSite): VerificationStep {
  const loc: Location = { kind: "tool", tool_name: site.tool_name };
  return {
    step_type: "inspect-schema",
    instruction:
      `Inspect the MCP tools/list response for "${site.tool_name}". Confirm the ` +
      `input_schema field is null or absent.`,
    target: loc,
    expected_observation: `input_schema is null/undefined — no structural contract.`,
  };
}

export function stepDefineSchema(site: SchemalessSite): VerificationStep {
  const loc: Location = { kind: "tool", tool_name: site.tool_name };
  return {
    step_type: "compare-baseline",
    instruction:
      `Define a JSON Schema for the tool's inputs. Include every parameter the ` +
      `handler reads, with a declared type and at least one constraint per field. ` +
      `Reject calls that do not match the schema.`,
    target: loc,
    expected_observation:
      `Tool declares a non-empty input_schema with typed properties and ` +
      `additionalProperties: false.`,
  };
}
