/**
 * N3 — Named VerificationStep factories with structured source-code targets.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { IdAssignment, SourceLocation } from "./gather.js";

function targetOf(loc: SourceLocation): string {
  return `source_code:line ${loc.line}:column ${loc.column}`;
}

export function verifyRhsIsPredictable(fact: IdAssignment): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the file at ${targetOf(fact.location)} and inspect the assignment to ` +
      `${fact.target_identifier}. Confirm the right-hand side is ${fact.generator_kind} ` +
      `(expression: ${fact.rhs_expression}). A counter increment or Date.now()/timestamp ` +
      `expression produces predictable ids usable for response spoofing.`,
    target: targetOf(fact.location),
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
      `Read the full body of ${scope} at ${targetOf(fact.location)}. Confirm no call ` +
      `to crypto.randomUUID, crypto.randomBytes, crypto.getRandomValues, uuid(), ` +
      `nanoid(), cuid(), or ulid() appears in the id-assignment path.`,
    target: targetOf(fact.location),
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
    target: targetOf(fact.location),
    expected_observation:
      `Transport permits a second producer (MitM, shared proxy, multi-writer SSE) ` +
      `to race a response past the server. CVE-2025-6515 class applies.`,
  };
}
