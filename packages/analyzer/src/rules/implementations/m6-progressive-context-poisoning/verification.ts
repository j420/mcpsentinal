import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { AccumulationSite } from "./gather.js";

export function buildAccumulationInspectionStep(
  site: AccumulationSite,
): VerificationStep {
  const target: Location = site.location;
  return {
    step_type: "inspect-source",
    instruction:
      `Open the aggregated source at line ${site.line} and confirm the ` +
      `call uses the accumulation verb "${site.verb.label}" against a ` +
      `${site.context_label} (identifier fragment "${site.context_fragment}").`,
    target,
    expected_observation:
      `Line reads: "${site.line_text}". The call appends content to a ` +
      `persistent store whose contents are later consumed by the agent ` +
      `as context.`,
  };
}

export function buildBoundCheckStep(site: AccumulationSite): VerificationStep {
  const target: Location = site.location;
  return {
    step_type: "inspect-source",
    instruction:
      `Within ±6 lines of line ${site.line}, search for any of: ` +
      `limit, max_size, max_length, truncate, clear, reset, evict, ` +
      `expire, ttl. If absent, the accumulation is unbounded and attacker ` +
      `content accumulates indefinitely.`,
    target,
    expected_observation:
      site.bound_distance === null
        ? `No bound keyword found within the window — the accumulation is ` +
          `architecturally unbounded.`
        : `Bound "${site.bound_label}" found ${site.bound_distance} lines ` +
          `away. Verify it is actually applied to this accumulation call ` +
          `(not to an unrelated nearby variable).`,
  };
}

export function buildFeedbackLoopTraceStep(
  site: AccumulationSite,
): VerificationStep {
  const target: Location = site.location;
  return {
    step_type: "trace-flow",
    instruction:
      `Trace from the accumulation at line ${site.line} to the read side: ` +
      `identify the code path that reads the same store and feeds its ` +
      `contents into the model's prompt or context window. Confirm there ` +
      `is no integrity / provenance check between write and read.`,
    target,
    expected_observation:
      `A reader (vector-search / history-join / context-build) consumes ` +
      `the store without verifying content provenance, so adversary-` +
      `controlled writes flow back into the model on subsequent turns.`,
  };
}
