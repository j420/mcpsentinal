/**
 * N10 — Named VerificationStep factories with structured targets.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { HandshakeFact, SourceLocation } from "./gather.js";

function targetOf(loc: SourceLocation): string {
  return `source_code:line ${loc.line}:column ${loc.column}`;
}

export function verifyAcceptWithoutDeadline(fact: HandshakeFact): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the file at ${targetOf(fact.location)} and inspect the ${fact.accept_kind} ` +
      `constructor call ${fact.accept_expression}. Confirm no handshakeTimeout, ` +
      `headersTimeout, requestTimeout, AbortSignal.timeout, Promise.race, or ` +
      `per-socket setTimeout brackets the initialize read.`,
    target: targetOf(fact.location),
    expected_observation:
      `Server accepts connections without a handshake deadline. An idle connection ` +
      `that never sends initialize holds the slot indefinitely.`,
  };
}

export function verifyNoMaxConnections(fact: HandshakeFact): VerificationStep {
  const scope = fact.location.enclosing_function
    ? `function ${fact.location.enclosing_function}`
    : "module scope";
  return {
    step_type: "inspect-source",
    instruction:
      `Read the full body of ${scope} at ${targetOf(fact.location)}. Confirm no ` +
      `maxConnections, backlog, maxClients, or equivalent limit is set on the ` +
      `server. Without a limit, connection-exhaustion scales linearly with attacker bandwidth.`,
    target: targetOf(fact.location),
    expected_observation:
      `No maxConnections / backlog / maxClients property is set on the server instance.`,
  };
}

export function verifySlowlorisReproducible(fact: HandshakeFact): VerificationStep {
  return {
    step_type: "test-input",
    instruction:
      `Simulate Slowloris: open N TCP connections to the server (N = ulimit - 50) and ` +
      `never send initialize. Observe whether new legitimate clients time out. If they ` +
      `do, the handshake-deadline defect is live.`,
    target: targetOf(fact.location),
    expected_observation:
      `Held connections consume server slots; new connections are rejected or hang.`,
  };
}
