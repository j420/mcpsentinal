/**
 * Q6 verification-step builders.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { ImpersonationSite } from "./gather.js";

export function stepInspectClaim(site: ImpersonationSite): VerificationStep {
  return {
    step_type: "inspect-description",
    instruction:
      `Open the ${site.surface === "tool-description" ? "tool description" : "source location"} ` +
      `at the reported Location and confirm the text "${site.observed}" is present. ` +
      `The vendor token "${site.vendor}" appears as a self-declared identity ` +
      `with no external attestation.`,
    target: site.location,
    expected_observation:
      `The identity claim is emitted by the server itself — no signed ` +
      `registry entry or cryptographic provenance is verifiable from the ` +
      `metadata alone.`,
  };
}

export function stepVerifyNamespace(site: ImpersonationSite): VerificationStep {
  return {
    step_type: "check-dependency",
    instruction:
      `Cross-reference "${site.vendor}" against the vendor's official ` +
      `namespace registry (npm @<vendor>/*, PyPI <vendor>-*, the vendor's ` +
      `signed MCP registry entry). If the server is NOT in the official ` +
      `namespace, the identity claim is impersonation.`,
    target: site.location,
    expected_observation:
      `The server's publisher namespace does not match the vendor it ` +
      `claims to represent — impersonation confirmed.`,
  };
}
