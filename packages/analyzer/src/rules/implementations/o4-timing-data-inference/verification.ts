/** O4 verification steps — structured Location targets. */
import type { VerificationStep } from "../../../evidence.js";
import type { TimingSite } from "./gather.js";

export function stepInspectDelay(site: TimingSite): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open this line. Confirm the delay call (${site.delayCallee}) runs on ` +
      `the normal control-flow path of a function that branches on data-` +
      `dependent identifiers (secret, password, match, etc.).`,
    target: site.location,
    expected_observation:
      `A ${site.delayKind} call on a live code path inside a function that ` +
      `reads a sensitive identifier.`,
  };
}

export function stepCheckTimingSafe(site: TimingSite): VerificationStep {
  return {
    step_type: "trace-flow",
    instruction: site.hasTimingSafe
      ? `A timing-safe identifier (timingSafeEqual / compare_digest / constantTime) ` +
        `is present in the enclosing function. Confirm it guards the SAME ` +
        `comparison that precedes the delay — not just any other comparison.`
      : `No timing-safe comparison (crypto.timingSafeEqual, hmac.compare_digest, ` +
        `constant-time library call) found in the enclosing function. Confirm ` +
        `by reading the function body.`,
    target: site.enclosingFunctionLocation ?? site.location,
    expected_observation: site.hasTimingSafe
      ? `timingSafeEqual invocation adjacent to the flagged comparison.`
      : `No timing-safe comparison in enclosing scope.`,
  };
}

export function stepCheckJitter(site: TimingSite): VerificationStep {
  return {
    step_type: "trace-flow",
    instruction: site.hasJitter
      ? `Math.random-based jitter was found in the enclosing scope. Confirm ` +
        `it is added to (not multiplied with) the delay value so low-bit ` +
        `entropy is actually observable.`
      : `No Math.random jitter found. The delay is deterministic from ` +
        `observable inputs.`,
    target: site.enclosingFunctionLocation ?? site.location,
    expected_observation: site.hasJitter
      ? `Math.random() additive jitter.`
      : `No jitter — delay is deterministic.`,
  };
}
