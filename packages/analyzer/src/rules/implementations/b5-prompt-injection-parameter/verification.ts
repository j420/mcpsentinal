import type { VerificationStep } from "../../../evidence.js";
import type { B5Site } from "./gather.js";
import { paramLocation } from "./gather.js";

export function stepInspectParamDescription(site: B5Site): VerificationStep {
  return {
    step_type: "inspect-description",
    instruction:
      `Inspect the description field for parameter "${site.parameter_name}" of ` +
      `tool "${site.tool_name}". Locate the phrase "${site.observed}" at offset ` +
      `${site.offset}. Confirm the description is a directive to the LLM, not ` +
      `factual type/format information.`,
    target: paramLocation(site.tool_name, site.parameter_name),
    expected_observation:
      `The parameter description contains ${site.kind} "${site.label}" at offset ` +
      `${site.offset} — an injection signal the LLM will read when filling the argument.`,
  };
}

export function stepRemoveDirective(site: B5Site): VerificationStep {
  return {
    step_type: "compare-baseline",
    instruction:
      `Replace the description for "${site.parameter_name}" with factual text only ` +
      `(e.g. "Absolute filesystem path. Must start with '/'. Max 1024 chars."). ` +
      `No imperative language, no role prefixes, no authority claims.`,
    target: paramLocation(site.tool_name, site.parameter_name),
    expected_observation: `A rewritten description produces zero B5 matches.`,
  };
}
