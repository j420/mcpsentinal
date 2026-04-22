/**
 * C11 verification-step builders — every step's `target` is a structured
 * Location.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { RedosFact, C11LeakKind } from "./gather.js";

function describeKind(kind: C11LeakKind): string {
  switch (kind) {
    case "user-controlled-pattern":
      return "a `new RegExp(<expr>)` whose pattern is user-controllable";
    case "nested-quantifier":
      return "a regex with nested quantifiers ((X+)+ / (X*)+ class)";
    case "alternation-overlap":
      return "a regex with alternation overlap ((a|a)+ / (a|ab)+ class)";
    case "polynomial-blowup":
      return "a regex with polynomial blow-up ((.*)*  / (.+)+ shape)";
  }
}

export function stepInspectRegexShape(fact: RedosFact): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the file at this position and confirm the regex really has ` +
      `the shape the rule reports. Run a ReDoS fuzzer (rxxr2, ` +
      `vuln-regex-detector, regexploit) against the literal to verify ` +
      `the worst-case input.`,
    target: fact.location,
    expected_observation:
      `${describeKind(fact.kind)}. Observed: \`${fact.observed}\`.`,
  };
}

export function stepCheckBoundedInput(fact: RedosFact): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      fact.mitigationPresent
        ? `A mitigation marker (RE2 import or maxLength / substring / slice ` +
          `bounding) was detected somewhere in the source. Confirm it ` +
          `applies to the input that reaches THIS regex — a length cap ` +
          `applied to a different code path does not protect this one.`
        : `Walk the file for any input-length cap before this regex use ` +
          `(\`.substring(0, N)\`, \`.slice(0, N)\`, schema-level maxLength). ` +
          `The rule found none — the regex receives unbounded input.`,
    target: fact.location,
    expected_observation:
      fact.mitigationPresent
        ? "A mitigation marker exists in the file but its scope needs review."
        : "No input-length cap and no linear-time engine in this source — the regex runs on unbounded input.",
  };
}

export function stepCheckEngineSwap(fact: RedosFact): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Confirm whether the codebase exposes an option to swap the regex ` +
      `engine to a linear-time alternative (re2, node-re2, RE2). Where the ` +
      `engine is fixed (V8 default), pair the regex with a hard input-` +
      `length cap and a per-request CPU budget.`,
    target: fact.location,
    expected_observation:
      "Either a linear-time engine import OR a hard input-length cap before regex use.",
  };
}
