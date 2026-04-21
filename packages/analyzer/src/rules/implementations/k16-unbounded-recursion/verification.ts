/**
 * K16 verification-step builders — every step carries a structured Location.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { RecursionCycle } from "./gather.js";

export function stepInspectCall(cycle: RecursionCycle): VerificationStep {
  const edgeLabel = describeEdge(cycle);
  return {
    step_type: "inspect-source",
    instruction:
      `Open the file at this line. Confirm the ${edgeLabel} closing the ` +
      `recursion cycle with entry \`${cycle.entryLabel}\`. Trace the ` +
      `control-flow path from this call back to the entry function and ` +
      `verify that no intermediate caller attenuates the depth (e.g. ` +
      `returns early on a size threshold, holds a visited-set, or passes ` +
      `a decrementing counter).`,
    target: cycle.callLocation,
    expected_observation:
      `A ${edgeLabel} at this location that re-enters the cycle ` +
      `{${cycle.cycleMembers.join(" → ")}} with no observable attenuation.`,
  };
}

export function stepInspectEntry(cycle: RecursionCycle): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the entry function of the recursion cycle. Inspect its ` +
      `parameter list for a declared depth / level / limit / counter ` +
      `parameter (checked names: depth, level, remaining, budget, maxDepth, ` +
      `maxLevel, maxRecursion, counter, iterations, step, hops, limit). ` +
      `If present, inspect the function body for a BinaryExpression ` +
      `comparing that parameter against a numeric literal or an ` +
      `UPPER_SNAKE constant — the comparison is the guard, not the ` +
      `parameter alone.`,
    target: cycle.entryLocation,
    expected_observation: cycle.hasDepthParameter
      ? `Depth parameter declared but no comparison (BinaryExpression) ` +
        `against a numeric literal or UPPER_SNAKE constant was observed.`
      : `No depth / level / limit parameter declared on the entry function.`,
  };
}

export function stepInspectCycleBreaker(cycle: RecursionCycle): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      cycle.hasCycleBreaker
        ? `A visited-set (Set / Map / WeakSet / WeakMap) with a .has / .add / ` +
          `.get / .set method call was observed in the entry function. Confirm ` +
          `the set is consulted on the SPECIFIC value being recursed into — a ` +
          `set consulted on an unrelated variable is not a mitigation.`
        : `Confirm the entry function body contains NO visited-set cycle ` +
          `breaker: inspect for \`new Set()\` / \`new Map()\` / \`new WeakSet()\` ` +
          `/ \`new WeakMap()\` constructors and subsequent .has / .add calls. ` +
          `Absence means adversarial input deterministically drives the ` +
          `recursion to its runtime limit.`,
    target: cycle.entryLocation,
    expected_observation: cycle.hasCycleBreaker
      ? `Visited-set observed but requires manual confirmation of applicability.`
      : `No visited-set cycle breaker in the entry function body.`,
  };
}

function describeEdge(cycle: RecursionCycle): string {
  switch (cycle.edgeKind) {
    case "direct-self-call":
      return `direct self-call to \`${cycle.entryLabel}\``;
    case "mutual-recursion":
      return `mutual-recursion call into the cycle {${cycle.cycleMembers.join(" → ")}}`;
    case "tool-call-roundtrip":
      return `MCP tool-call roundtrip into the cycle {${cycle.cycleMembers.join(" → ")}}`;
    case "emit-roundtrip":
      return `emitter/dispatcher roundtrip into the cycle {${cycle.cycleMembers.join(" → ")}}`;
  }
}
