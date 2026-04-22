/**
 * N1 — Named verification-step factories. Each step's `target` carries a
 * structured {@link Location} — not prose — so the audit trail is
 * reproducible without the original finding object.
 *
 * Wave-2 remediation (2026-04-21): converted prose `target` strings to
 * kind:"source" Locations per Rule Standard v2.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { SourceLocation } from "./gather.js";

/**
 * Convert the gather-stage {@link SourceLocation} into the canonical
 * {@link Location} used by v2 evidence chains. The concatenated source
 * corpus has no single filename, so the synthetic `source_code` anchor
 * is used consistently with other protocol-surface rules.
 */
export function toLocation(loc: SourceLocation): Location {
  return { kind: "source", file: "source_code", line: loc.line, col: loc.column };
}

function renderAnchor(loc: SourceLocation): string {
  return `source_code:line ${loc.line}:column ${loc.column}`;
}

export function verifyIterationIsUnbounded(loc: SourceLocation, method: string): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the enclosing function at ${renderAnchor(loc)} and verify that the batch ` +
      `iteration via ${method}() is not preceded by a size guard. ` +
      `Acceptable guards are: explicit .length comparison against a numeric literal, ` +
      `a .slice(0, N) before iteration, a throttle()/rateLimit() wrapper, or a thrown ` +
      `error when the batch exceeds a constant.`,
    target: toLocation(loc),
    expected_observation:
      `No size guard, no .slice, no throttle; batch iteration runs once per element ` +
      `with no upper bound.`,
  };
}

export function verifyEnclosingScopeHasNoLimit(loc: SourceLocation, enclosingName: string | null): VerificationStep {
  const scopeLabel = enclosingName ? `function ${enclosingName}` : "enclosing function";
  return {
    step_type: "inspect-source",
    instruction:
      `Read the entire body of the ${scopeLabel} containing the call at ${renderAnchor(loc)}. ` +
      `Confirm it contains no variable named max/limit/maxBatch/maxRequests, no .length ` +
      `comparison operators, and no throttle/debounce/rateLimit helper calls.`,
    target: toLocation(loc),
    expected_observation:
      `The enclosing function contains zero size-limit vocabulary and zero throttling ` +
      `vocabulary. The handler processes batches of arbitrary length.`,
  };
}

export function verifyNoTransportLayerLimit(loc: SourceLocation): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Inspect the server's transport configuration (Express/Fastify body parser, ` +
      `Node http.Server max-json-size, reverse proxy body limit). If a transport-level ` +
      `byte limit exists it only bounds bytes, not batch entry count — document the ` +
      `per-entry cost estimate to confirm this is still an amplification vector.`,
    target: toLocation(loc),
    expected_observation:
      `Transport limit (if any) is measured in bytes; per-entry work is unbounded by ` +
      `batch length.`,
  };
}
