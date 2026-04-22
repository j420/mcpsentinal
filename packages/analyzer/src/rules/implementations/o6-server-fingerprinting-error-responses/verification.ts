/**
 * O6 verification-step builders.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { FingerprintSurfaceSite } from "./gather.js";

export function stepInspectResponseConstruction(
  site: FingerprintSurfaceSite,
): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the source at the reported Location and confirm the ` +
      `response-construction node (${site.responseShape}) embeds the ` +
      `fingerprint-surface identifier "${site.surfaceToken}" ` +
      `(kind: ${site.kind}) in the outbound payload. A safe response ` +
      `emits a generic error message ("Internal server error") ` +
      `without any process / os / path / dependency metadata.`,
    target: site.location,
    expected_observation:
      `The identifier flows straight from a Node / os / db / ` +
      `package.json introspection primitive into a tool response ` +
      `or thrown Error payload. CVE-2026-29787 demonstrated exactly ` +
      `this pattern on mcp-memory-service /health/detailed.`,
  };
}

export function stepCheckSanitizerAdjacency(
  site: FingerprintSurfaceSite,
): VerificationStep {
  const target: Location = site.enclosingFunctionLocation ?? site.location;
  return {
    step_type: "check-config",
    instruction:
      `Inspect the enclosing function and confirm whether a ` +
      `sanitiser (pino.redact, sanitizeError, scrub_error, mask, ` +
      `filterErrorPayload) is wired into the response path before ` +
      `the emitter. A sanitiser adjacent to the response call ` +
      `demotes the finding (the author intended scrubbed output).`,
    target,
    expected_observation:
      site.hasSanitizer
        ? `Observed sanitiser: ${site.matchedSanitizer ?? "<unknown>"} — ` +
          `confirm it actually runs on the flagged branch.`
        : `No sanitiser identifier in scope — the fingerprint surface ` +
          `reaches the caller unfiltered.`,
  };
}

export function stepAuthBranchDivergence(
  site: FingerprintSurfaceSite,
): VerificationStep {
  const target: Location = site.enclosingFunctionLocation ?? site.location;
  return {
    step_type: "trace-flow",
    instruction:
      `Walk the enclosing function and check whether the flagged ` +
      `emission sits inside an auth-gated branch. Look for the ` +
      `opposite (unauthenticated) branch — if it also emits any ` +
      `fingerprint surface, the auth gate offers no protection.`,
    target,
    expected_observation:
      site.authGated
        ? `Flagged branch sits behind an auth predicate. The auth ` +
          `gate does NOT suppress the finding — an attacker who ` +
          `steals a session still observes the full fingerprint ` +
          `surface. Confirm the unauthenticated branch emits a ` +
          `generic payload.`
        : `Flagged branch is not auth-gated — the fingerprint ` +
          `surface is reachable by any caller that triggers the ` +
          `response path.`,
  };
}
