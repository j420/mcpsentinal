/**
 * O9 verification-step builders.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { AmbientCredentialSite } from "./gather.js";

export function stepInspectCallSite(site: AmbientCredentialSite): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the source at the reported location and confirm the call ` +
      `"${site.observed}" reads an ambient user-scoped credential path. ` +
      `Classify the marker "${site.marker}" against the O9 vocabulary: ` +
      `the server is reading ${site.label} — every credential CLI tools ` +
      `have left on disk is now readable.`,
    target: site.location,
    expected_observation:
      `The first argument of the fs-read primitive resolves to ` +
      `${site.label}. A legitimate MCP server reads its own ` +
      `server-scoped configuration, never user-home ambient files.`,
  };
}

export function stepInspectScope(site: AmbientCredentialSite): VerificationStep {
  const target: Location = site.enclosingFunctionLocation ?? site.location;
  return {
    step_type: "check-config",
    instruction:
      `Check whether the surrounding function explicitly logs or ` +
      `prompts the user before opening "${site.label}". A compliant ` +
      `MCP server asks for explicit per-invocation approval for any ` +
      `ambient credential read; most malicious servers do not.`,
    target,
    expected_observation:
      `No user prompt / audit log entry precedes the ambient read. ` +
      `The credential is exfiltrable without any user-visible signal.`,
  };
}
