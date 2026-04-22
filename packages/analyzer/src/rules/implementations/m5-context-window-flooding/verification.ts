/**
 * M5 verification steps — named factories, structured Location targets.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { FloodSite } from "./gather.js";

export function stepInspectDescription(site: FloodSite): VerificationStep {
  const classes = Array.from(new Set(site.matched_signals.map((m) => m.cls))).join(", ");
  return {
    step_type: "inspect-description",
    instruction:
      `Read the tool description. Confirm the following flooding signal ` +
      `classes: ${classes || "(description length anomaly only)"}. Each ` +
      `signal is a promise of unbounded / verbose output that consumes ` +
      `context-window tokens when the tool runs.`,
    target: site.location,
    expected_observation:
      `Tool "${site.tool_name}" description asserts ${site.matched_signals.length} ` +
      `flooding signal(s); description is ${site.description_length} chars long.`,
  };
}

export function stepCheckPagination(site: FloodSite): VerificationStep {
  return {
    step_type: "inspect-schema",
    instruction: site.has_pagination
      ? `Pagination/limit tokens were detected in the description OR schema. ` +
        `Open the input_schema and confirm the pagination parameter is REQUIRED ` +
        `or has a sensible default — a pagination param with default "all" is ` +
        `equivalent to no pagination.`
      : site.has_no_pagination_claim
        ? `Description explicitly claims "no limit" / "without pagination". ` +
          `Confirm the tool is intentionally unbounded and measure actual ` +
          `response sizes in a canary test.`
        : `No pagination or limit parameter found in description or schema. ` +
          `Confirm the tool output is bounded by construction (e.g. it ` +
          `queries a finite lookup table) before dismissing this finding.`,
    target: site.schema_location ?? site.location,
    expected_observation: site.has_pagination
      ? `A pagination parameter with sensible default or required flag.`
      : `No pagination parameter.`,
  };
}

export function stepCheckSchemaFlag(site: FloodSite): VerificationStep {
  if (site.unbounded_schema_field !== null && site.schema_location !== null) {
    return {
      step_type: "inspect-schema",
      instruction:
        `The input schema declares a parameter named "${site.unbounded_schema_field}" ` +
        `— this is an explicit unbounded-output opt-in. Verify the parameter has ` +
        `a server-side hard cap or rate limit.`,
      target: site.schema_location,
      expected_observation:
        `Parameter "${site.unbounded_schema_field}" present in input_schema.`,
    };
  }
  return {
    step_type: "inspect-schema",
    instruction:
      `No unbounded-output flag found in the schema. Confirm there is no ` +
      `parameter resembling 'include_all' / 'dump_all' / 'no_limit' / ` +
      `'full_output' that escalates the tool to unbounded mode.`,
    target: site.location,
    expected_observation: `No unbounded-output flag in input_schema.`,
  };
}
