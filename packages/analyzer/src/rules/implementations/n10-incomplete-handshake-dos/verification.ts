/**
 * N10 — Named VerificationStep factories with structured {@link Location}
 * targets (Rule Standard v2 §4).
 *
 * Wave-2 remediation (2026-04-21): prose target strings → Locations.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { HandshakeFact, SourceLocation } from "./gather.js";

export function toLocation(loc: SourceLocation): Location {
  return { kind: "source", file: "source_code", line: loc.line, col: loc.column };
}

function renderAnchor(loc: SourceLocation): string {
  return `source_code:line ${loc.line}:column ${loc.column}`;
}

export function verifyAcceptWithoutDeadline(fact: HandshakeFact): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the file at ${renderAnchor(fact.location)} and inspect the ${fact.accept_kind} ` +
      `constructor call ${fact.accept_expression}. Confirm no handshakeTimeout, ` +
      `headersTimeout, requestTimeout, AbortSignal.timeout, Promise.race, or ` +
      `per-socket setTimeout brackets the initialize read.`,
    target: toLocation(fact.location),
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
      `Read the full body of ${scope} at ${renderAnchor(fact.location)}. Confirm no ` +
      `maxConnections, backlog, maxClients, or equivalent limit is set on the ` +
      `server. Without a limit, connection-exhaustion scales linearly with attacker bandwidth.`,
    target: toLocation(fact.location),
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
    target: toLocation(fact.location),
    expected_observation:
      `Held connections consume server slots; new connections are rejected or hang.`,
  };
}
