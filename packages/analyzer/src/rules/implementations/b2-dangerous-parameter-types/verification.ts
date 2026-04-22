import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { DangerousSite } from "./gather.js";

export function stepInspectParams(site: DangerousSite): VerificationStep {
  const loc: Location = { kind: "tool", tool_name: site.tool_name };
  const list = site.params.map((p) => `${p.name} (${p.sink})`).join(", ");
  return {
    step_type: "inspect-schema",
    instruction:
      `Inspect the input_schema of tool "${site.tool_name}" and confirm these ` +
      `parameter names are present: ${list}.`,
    target: loc,
    expected_observation:
      `${site.params.length} parameter(s) have dangerous names that advertise ` +
      `direct paths to execution / file-write / network / query sinks.`,
  };
}

export function stepInspectHandler(site: DangerousSite): VerificationStep {
  const loc: Location = { kind: "tool", tool_name: site.tool_name };
  return {
    step_type: "inspect-source",
    instruction:
      `Open the tool handler for "${site.tool_name}" and trace where each ` +
      `dangerous-named parameter flows. Confirm validation is present BEFORE the ` +
      `parameter reaches the sink (exec / query / eval / file write / HTTP fetch).`,
    target: loc,
    expected_observation:
      `Handler validates every dangerous parameter before execution — or (the finding case) ` +
      `passes the parameter raw to the sink.`,
  };
}
