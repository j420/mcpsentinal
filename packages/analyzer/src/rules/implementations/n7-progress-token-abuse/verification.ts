/**
 * N7 — Named VerificationStep factories. Every step's `target` is a
 * structured {@link Location} (Rule Standard v2 §4).
 *
 * Wave-2 remediation (2026-04-21): prose target strings → Locations.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { ProgressTokenFact, SourceLocation } from "./gather.js";

export function toLocation(loc: SourceLocation): Location {
  return { kind: "source", file: "source_code", line: loc.line, col: loc.column };
}

function renderAnchor(loc: SourceLocation): string {
  return `source_code:line ${loc.line}:column ${loc.column}`;
}

export function verifyTokenSource(fact: ProgressTokenFact): VerificationStep {
  const describe =
    fact.source_kind === "user-input"
      ? `directly from user-controlled input (${fact.rhs_expression})`
      : `from a predictable server-local expression (${fact.rhs_expression}, ${fact.source_kind})`;
  return {
    step_type: "inspect-source",
    instruction:
      `Open the file at ${renderAnchor(fact.location)} and confirm the progress token ` +
      `${fact.target_identifier} is sourced ${describe}. A cryptographically random ` +
      `generator is not invoked on this path.`,
    target: toLocation(fact.location),
    expected_observation:
      `${fact.target_identifier} = ${fact.rhs_expression}; no crypto random source.`,
  };
}

export function verifyNoOwnershipValidation(fact: ProgressTokenFact): VerificationStep {
  const scope = fact.location.enclosing_function
    ? `function ${fact.location.enclosing_function}`
    : "enclosing scope";
  return {
    step_type: "inspect-source",
    instruction:
      `Read the full body of ${scope}. Confirm the server never checks that the ` +
      `progress token was issued for the current session/request before accepting it ` +
      `as a correlation key. MCP spec 2025-03-26 §5.1 does not mandate ownership ` +
      `validation; the server MUST enforce it explicitly.`,
    target: toLocation(fact.location),
    expected_observation:
      `No lookup against an active-request map, no sessionId-token binding check, ` +
      `no signed-token verification.`,
  };
}

export function verifyNotificationsEmit(fact: ProgressTokenFact): VerificationStep {
  return {
    step_type: "trace-flow",
    instruction:
      `Trace the progress token from ${renderAnchor(fact.location)} to the notifications/progress ` +
      `emission site. Confirm the token reaches the outbound payload without ` +
      `rebinding through a cryptographic mapping.`,
    target: toLocation(fact.location),
    expected_observation:
      `Progress token flows unchanged into the notifications/progress payload that ` +
      `reaches the wire.`,
  };
}
