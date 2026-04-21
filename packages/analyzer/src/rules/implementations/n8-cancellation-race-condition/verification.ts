/**
 * N8 — Named VerificationStep factories with structured targets.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { CancelRaceFact, SourceLocation } from "./gather.js";

function targetOf(loc: SourceLocation): string {
  return `source_code:line ${loc.line}:column ${loc.column}`;
}

export function verifyCancelHandlerMutates(fact: CancelRaceFact): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the file at ${targetOf(fact.location)}. Confirm this is a ` +
      `${fact.handler_kind} cancel-path that invokes ${fact.mutation_verb}. The ` +
      `mutation happens in response to cancellation without atomic guarantees.`,
    target: targetOf(fact.location),
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
      `Read the full body of ${scope} at ${targetOf(fact.location)}. Confirm no ` +
      `beginTransaction/startTransaction/transaction()/atomic()/lock()/mutex()/` +
      `acquire() call brackets the mutation. Without an atomic guard, the ` +
      `cancel-and-rollback path is a CWE-367 TOCTOU race.`,
    target: targetOf(fact.location),
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
    target: targetOf(fact.location),
    expected_observation:
      `Cancel handler mutates state (${fact.mutation_verb}) after the original ` +
      `operation has already committed — the handler is not aware of the completion.`,
  };
}
