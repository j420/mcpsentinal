import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { I5Fact } from "./gather.js";

export function stepInspectResource(fact: I5Fact): VerificationStep {
  const target: Location = {
    kind: "resource",
    uri: fact.resource_uri,
    field: "name",
  };
  return {
    step_type: "inspect-schema",
    instruction:
      `Open the server manifest and locate the resource declaration for ` +
      `"${fact.resource_name}". Confirm whether the name collides with the ` +
      `tool "${fact.tool_name}" (match kind: ${fact.match_kind}).`,
    target,
    expected_observation:
      `A resource and a tool share the same ${fact.match_kind} name — AI ` +
      `clients may route a user request to either surface ambiguously.`,
  };
}

export function stepInspectTool(fact: I5Fact): VerificationStep {
  const target: Location = { kind: "tool", tool_name: fact.tool_name };
  return {
    step_type: "inspect-schema",
    instruction:
      `Open the tool "${fact.tool_name}" in the server manifest. Confirm ` +
      `whether the tool has destructive side effects that would be ` +
      `unintended if invoked via name confusion when the user intended ` +
      `resource access.`,
    target,
    expected_observation:
      fact.common_tool_hit?.destructive_by_convention
        ? `The tool is catalogued as destructive-by-convention ` +
          `(${fact.common_tool_hit.canonical_purpose}). Collision with a ` +
          `resource of the same name is high-risk.`
        : `The tool side-effect profile is indeterminate from the tool name ` +
          `alone; inspect the schema.`,
  };
}
