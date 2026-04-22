/**
 * Q3 verification-step builders.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { LocalhostBindSite } from "./gather.js";

export function stepInspectBind(site: LocalhostBindSite): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the listener call "${site.observed}" and confirm the host ` +
      `argument is "${site.host}" (localhost class). Verify the ` +
      `receiver chain does${site.mcpTokenOnReceiver ? "" : " not"} ` +
      `mention an MCP token. Classify this bind as exposing the MCP ` +
      `tool-invocation surface without mutual auth.`,
    target: site.location,
    expected_observation:
      `Listener bound to "${site.host}" is reachable by any local ` +
      `process OR any website exploiting DNS rebinding.`,
  };
}

export function stepCheckAuth(site: LocalhostBindSite): VerificationStep {
  const target: Location = site.enclosingFunctionLocation ?? site.location;
  return {
    step_type: "check-config",
    instruction:
      `Walk the enclosing function for an auth identifier ` +
      `(authorization / bearer / sharedSecret / apiKey / ` +
      `authenticate). If none is present, the MCP tool-invocation ` +
      `surface is unauthenticated.`,
    target,
    expected_observation:
      site.enclosingHasAuth
        ? `Observed auth identifier: ${site.matchedAuth ?? "<unknown>"} — the site is demoted.`
        : `No auth identifier in scope — the bind is unconditional.`,
  };
}
