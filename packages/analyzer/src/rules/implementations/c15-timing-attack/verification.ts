/**
 * C15 verification-step builders — every step's `target` is a structured
 * Location.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { TimingFact, C15LeakKind } from "./gather.js";

function describeKind(kind: C15LeakKind): string {
  switch (kind) {
    case "strict-equality":
      return "a `===` / `!==` comparison between a secret and a request value";
    case "loose-equality":
      return "a `==` / `!=` comparison between a secret and a request value";
    case "starts-ends-with":
      return "a `.startsWith` / `.endsWith` / `.includes` / `.indexOf` call between a secret and a request value";
    case "python-equality":
      return "a Python `==` comparison between a secret and a request value";
  }
}

export function stepInspectComparison(fact: TimingFact): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the file at this position and confirm the comparison really ` +
      `crosses the trust boundary — the secret on one side, a request-` +
      `derived value on the other. Replace with crypto.timingSafeEqual ` +
      `(Node.js Buffer.from on both sides) or hmac.compare_digest ` +
      `(Python bytes on both sides) before re-deploying.`,
    target: fact.location,
    expected_observation:
      `${describeKind(fact.kind)}. Secret operand: \`${fact.secretSide}\`; ` +
      `request operand: \`${fact.requestSide}\`. Observed: \`${fact.observed}\`.`,
  };
}

export function stepCheckTimingSafeImport(fact: TimingFact): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      fact.mitigationPresent
        ? `A timing-safe comparison helper (timingSafeEqual / compare_digest / ` +
          `constant_time_compare / secure_compare) was detected somewhere in ` +
          `the source. Confirm THIS comparison uses it — a sibling helper ` +
          `that exists but is not invoked here does not protect THIS ` +
          `comparison.`
        : `Walk the file for any timing-safe comparison helper ` +
          `(timingSafeEqual / compare_digest / constant_time_compare / ` +
          `secure_compare). The rule found none — the comparison is ` +
          `vulnerable.`,
    target: fact.location,
    expected_observation:
      fact.mitigationPresent
        ? "A timing-safe helper exists in the source but the comparison at this position does not use it."
        : "No timing-safe helper anywhere in the source — every secret comparison in this file is vulnerable.",
  };
}

export function stepCheckRateLimit(fact: TimingFact): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Check whether the route that contains this comparison is rate-` +
      `limited. Rate-limiting alone does NOT close a timing oracle (the ` +
      `attacker just samples slower) but its absence makes the attack ` +
      `fast and detectable; a hard-coded length-equal check + ` +
      `timingSafeEqual is the only complete remediation.`,
    target: fact.location,
    expected_observation:
      "Rate-limit middleware on the route + length-equal pre-check + crypto.timingSafeEqual.",
  };
}
