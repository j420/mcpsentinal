/**
 * O8 verification-step builders.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { TimingSite } from "./gather.js";

export function stepInspectTimingCall(site: TimingSite): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the source at the reported location and confirm the timing ` +
      `primitive "${site.primitive}" is called with a non-constant delay ` +
      `argument ("${site.delayExpression}"). A legitimate rate-limiter ` +
      `uses a configured constant (setTimeout(cb, 1000) or ` +
      `setTimeout(cb, RATE_LIMIT_MS)); a timing channel reads a variable ` +
      `whose value is influenced by secret data.`,
    target: site.location,
    expected_observation:
      `The delay argument reads ${site.delayReadsIdentifier ?? "a non-literal expression"}. ` +
      (site.matchedDataHint
        ? `The identifier name "${site.matchedDataHint}" is a positive data-dependency hint.`
        : `No counter-identifier name (retryCount / attempt / delayMs / backoff) ` +
          `is present — the delay is plausibly data-derived.`),
  };
}

export function stepCheckConstantTimeFloor(site: TimingSite): VerificationStep {
  const target: Location = site.enclosingFunctionLocation ?? site.location;
  return {
    step_type: "check-config",
    instruction:
      `Inspect the enclosing function and confirm whether a ` +
      `constant-time response floor is applied (e.g. the tool ` +
      `wraps its handler in a fixed-duration promise, or runtime ` +
      `middleware pads every response to a uniform latency). A ` +
      `constant-time floor nullifies O8 completely.`,
    target,
    expected_observation:
      `No constant-time floor observed. The handler returns as soon as ` +
      `${site.primitive} resolves, so the measured latency directly ` +
      `carries the delay expression's value.`,
  };
}

export function stepTraceDataDependency(site: TimingSite): VerificationStep {
  const target: Location = site.enclosingFunctionLocation ?? site.location;
  return {
    step_type: "trace-flow",
    instruction:
      `Walk backward from the delay argument to its definition. If the ` +
      `identifier ultimately reads from a secret, a tool-input parameter, ` +
      `a response body, or any server state that varies by caller, the ` +
      `timing channel is real. If the identifier resolves to a ` +
      `deterministic constant or a counter, the site is a false positive.`,
    target,
    expected_observation:
      `The reviewer should find the delay expression reading ` +
      `${site.delayReadsIdentifier ?? "a non-constant expression"} that is not ` +
      `provably bounded by a configured constant.`,
  };
}
