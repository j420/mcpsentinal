import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { InjectSite } from "./gather.js";

export function buildUserInputTraceStep(site: InjectSite): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `At line ${site.line}, confirm ${site.user_source.label} flows into ` +
      `${site.error_surface.label} without passing through a sanitiser.`,
    target: site.location as Location,
    expected_observation:
      `Line reads: "${site.line_text}". User-controlled bytes appear ` +
      `directly in the error surface.`,
  };
}

export function buildErrorPathTraceStep(site: InjectSite): VerificationStep {
  return {
    step_type: "trace-flow",
    instruction:
      `Trace from the error construction at line ${site.line} to the ` +
      `JSON-RPC error envelope. Most MCP SDKs wrap an Error's .message ` +
      `into the response's error.message field and the attached .data ` +
      `into error.data.`,
    target: site.location as Location,
    expected_observation:
      `error.message or error.data in the wire response contains ` +
      `adversary-controlled bytes.`,
  };
}

export function buildSanitiserCheckStep(site: InjectSite): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Within ±4 lines of line ${site.line}, look for a sanitiser ` +
      `(escape / sanitise / strip / redact / truncate). If absent, the ` +
      `error envelope carries attacker bytes intact.`,
    target: site.location as Location,
    expected_observation:
      site.sanitiser_distance !== null
        ? `Sanitiser "${site.sanitiser_label}" at distance ${site.sanitiser_distance} — ` +
          `confirm it applies to this error path.`
        : `No sanitiser in the window. Path is unsanitised.`,
  };
}
