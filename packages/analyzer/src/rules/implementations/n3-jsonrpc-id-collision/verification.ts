/**
 * N3 — Named VerificationStep factories with structured {@link Location}
 * targets per Rule Standard v2 §4.
 *
 * Wave-2 remediation (2026-04-21): converted prose `target` strings to
 * kind:"source" Locations.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { IdAssignment, SourceLocation } from "./gather.js";

export function toLocation(loc: SourceLocation): Location {
  return { kind: "source", file: "source_code", line: loc.line, col: loc.column };
}

function renderAnchor(loc: SourceLocation): string {
  return `source_code:line ${loc.line}:column ${loc.column}`;
}

export function verifyRhsIsPredictable(fact: IdAssignment): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the file at ${renderAnchor(fact.location)} and inspect the assignment to ` +
      `${fact.target_identifier}. Confirm the right-hand side is ${fact.generator_kind} ` +
      `(expression: ${fact.rhs_expression}). A counter increment or Date.now()/timestamp ` +
      `expression produces predictable ids usable for response spoofing.`,
    target: toLocation(fact.location),
    expected_observation:
      `${fact.target_identifier} = ${fact.rhs_expression} — monotonic or predictable ` +
      `generator, not a cryptographic random source.`,
  };
}

export function verifyNoCryptoGenerator(fact: IdAssignment): VerificationStep {
  const scope = fact.location.enclosing_function
    ? `function ${fact.location.enclosing_function}`
    : "enclosing scope";
  return {
    step_type: "inspect-source",
    instruction:
      `Read the full body of ${scope} at ${renderAnchor(fact.location)}. Confirm no call ` +
      `to crypto.randomUUID, crypto.randomBytes, crypto.getRandomValues, uuid(), ` +
      `nanoid(), cuid(), or ulid() appears in the id-assignment path.`,
    target: toLocation(fact.location),
    expected_observation:
      `No cryptographic random generator is invoked on the id-assignment path; the ` +
      `predictable id reaches the wire.`,
  };
}

export function verifyTransportAllowsSpoofing(fact: IdAssignment): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Confirm the transport in use (Streamable HTTP, SSE, WebSocket) allows any ` +
      `second party to write into the client's response stream. TLS between a single ` +
      `client and server is insufficient — a compromised intermediary or multi-writer ` +
      `transport enables the collision attack.`,
    target: toLocation(fact.location),
    expected_observation:
      `Transport permits a second producer (MitM, shared proxy, multi-writer SSE) ` +
      `to race a response past the server. CVE-2025-6515 class applies.`,
  };
}
