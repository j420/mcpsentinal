/**
 * N8 — Named VerificationStep factories with structured {@link Location}
 * targets (Rule Standard v2 §4).
 *
 * Wave-2 remediation (2026-04-21): prose target strings → Locations.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { CancelRaceFact, SourceLocation } from "./gather.js";

export function toLocation(loc: SourceLocation): Location {
  return { kind: "source", file: "source_code", line: loc.line, col: loc.column };
}

function renderAnchor(loc: SourceLocation): string {
  return `source_code:line ${loc.line}:column ${loc.column}`;
}

export function verifyCancelHandlerMutates(fact: CancelRaceFact): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the file at ${renderAnchor(fact.location)}. Confirm this is a ` +
      `${fact.handler_kind} cancel-path that invokes ${fact.mutation_verb}. The ` +
      `mutation happens in response to cancellation without atomic guarantees.`,
    target: toLocation(fact.location),
    expected_observation:
      `Cancel handler contains a mutation call (${fact.mutation_verb}) and no ` +
      `transaction/lock wrapper.`,
  };
}

export function verifyNoTransactionOrLock(fact: CancelRaceFact): VerificationStep {
  const scope = fact.location.enclosing_function
    ? `function ${fact.location.enclosing_function}`
    : "enclosing scope";
  return {
    step_type: "inspect-source",
    instruction:
      `Read the full body of ${scope} at ${renderAnchor(fact.location)}. Confirm no ` +
      `beginTransaction/startTransaction/transaction()/atomic()/lock()/mutex()/` +
      `acquire() call brackets the mutation. Without an atomic guard, the ` +
      `cancel-and-rollback path is a CWE-367 TOCTOU race.`,
    target: toLocation(fact.location),
    expected_observation:
      `No transaction or lock vocabulary in the enclosing scope. The mutation is ` +
      `not bracketed by atomic begin/commit/rollback.`,
  };
}

export function verifyRuntimeRaceIsReproducible(fact: CancelRaceFact): VerificationStep {
  return {
    step_type: "trace-flow",
    instruction:
      `Simulate the race: issue a request that reaches the mutation site, wait until ` +
      `the mutation begins but before it commits, then send notifications/cancelled. ` +
      `Observe whether the cancel handler's mutation path runs after the original ` +
      `completion returns success.`,
    target: toLocation(fact.location),
    expected_observation:
      `Cancel handler mutates state (${fact.mutation_verb}) after the original ` +
      `operation has already committed — the handler is not aware of the completion.`,
  };
}
