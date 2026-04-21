/**
 * N2 — Named VerificationStep factories. Every step's `target` is a
 * structured source_code location, not a prose string.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { SourceLocation, NotificationFlood } from "./gather.js";

function targetOf(loc: SourceLocation): string {
  return `source_code:line ${loc.line}:column ${loc.column}`;
}

export function verifyEmissionInLoop(fact: NotificationFlood): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the file at ${targetOf(fact.location)} and confirm the notification ` +
      `call ${fact.call_expression}() is lexically inside a ${fact.loop_context} ` +
      `construct. Walk the AST parent chain upward and verify no intervening ` +
      `function boundary separates the call from the loop.`,
    target: targetOf(fact.location),
    expected_observation:
      `${fact.call_expression}() is executed once per iteration of the enclosing ` +
      `${fact.loop_context}. No early break, return, or delay interrupts the cycle.`,
  };
}

export function verifyNoThrottleVocabulary(fact: NotificationFlood): VerificationStep {
  const scope = fact.location.enclosing_function
    ? `function ${fact.location.enclosing_function}`
    : "enclosing scope";
  return {
    step_type: "inspect-source",
    instruction:
      `Read the full body of ${scope} at ${targetOf(fact.location)}. Search for ` +
      `any identifier matching throttle/debounce/rateLimit/sleep/delay/setTimeout ` +
      `and any break or early-return in the emission path. Absence of all of these ` +
      `confirms the notification emission is unbounded.`,
    target: targetOf(fact.location),
    expected_observation:
      `No throttle/debounce/rateLimit/sleep/delay/setTimeout call present; no ` +
      `break or early return in the loop body.`,
  };
}

export function verifyBackpressureAbsent(fact: NotificationFlood): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Inspect the transport configuration emitting these notifications (WebSocket, ` +
      `SSE, Streamable HTTP). Confirm no bounded outbound queue (e.g. ws.bufferedAmount ` +
      `check, SSE backpressure handler, or Streamable HTTP chunk flow control) ` +
      `protects downstream clients.`,
    target: targetOf(fact.location),
    expected_observation:
      `Transport layer has no bounded outbound queue; notifications reach the wire ` +
      `at producer speed with no consumer feedback.`,
  };
}
