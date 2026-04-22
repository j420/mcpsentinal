import type { VerificationStep } from "../../../evidence.js";
import type { LeakSite } from "./gather.js";

export function stepInspectReturn(site: LeakSite): VerificationStep {
  return {
    step_type: "trace-flow",
    instruction:
      `Open this line and confirm the identifier "${site.identifier}" carries ` +
      `a system prompt (not an unrelated variable that happens to share the ` +
      `name). Trace its data flow to the response sink.`,
    target: site.location,
    expected_observation:
      `Identifier "${site.identifier}" populates a response / return value.`,
  };
}

export function stepCheckRedaction(site: LeakSite): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the enclosing function and confirm there is no branch that ` +
      `calls redact / strip / mask / sanitize / filter / removePrompt on ` +
      `"${site.identifier}" before the response.`,
    target: site.enclosing_function_location ?? site.location,
    expected_observation: `No redaction call in enclosing function body.`,
  };
}

export function stepCheckConfig(site: LeakSite): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Check the tool's response schema. If "${site.identifier}" is an ` +
      `explicit field name, the tool documents the leak as a feature — ` +
      `confirm this is intentional and remove the field if not.`,
    target: site.location,
    expected_observation: `No system-prompt field in response schema.`,
  };
}
