import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { J4Hit } from "./gather.js";

export function stepInspectEndpoint(hit: J4Hit): VerificationStep {
  const target: Location = {
    kind: "source",
    file: "<server source>",
    line: hit.line_number,
  };
  return {
    step_type: "inspect-source",
    instruction:
      `Open server source at line ${hit.line_number}. Confirm endpoint ` +
      `"${hit.spec.path}" is exposed in production without authentication. ` +
      `Exposed info: ${hit.spec.exposed_info}.`,
    target,
    expected_observation: hit.line_preview,
  };
}

export function stepCheckAuth(): VerificationStep {
  const target: Location = {
    kind: "source",
    file: "<server source>",
    line: 1,
  };
  return {
    step_type: "check-config",
    instruction:
      "Confirm authentication / rate limiting on the health/debug endpoint. " +
      "If unauthenticated, strip the endpoint from the production build.",
    target,
    expected_observation:
      "Endpoint is accessible without authentication.",
  };
}
