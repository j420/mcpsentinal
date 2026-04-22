import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { DowngradeSite } from "./gather.js";

export function buildEchoInspectionStep(site: DowngradeSite): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open line ${site.line} and confirm the server's initialize path ` +
      `reflects the client-proposed protocolVersion (${site.echo_label}).`,
    target: site.location as Location,
    expected_observation: `Line reads: "${site.line_text}".`,
  };
}

export function buildEnforcementCheckStep(site: DowngradeSite): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Within ±8 lines, look for reject / throw / minProtocolVersion / ` +
      `supportedVersions / semver comparator. Absence = the server will ` +
      `agree to any claimed version.`,
    target: site.location as Location,
    expected_observation:
      site.enforcement_present
        ? `Enforcement "${site.enforcement_label}" found ${site.enforcement_distance} ` +
          `line(s) away — confirm it actually guards this path.`
        : `No enforcement keyword within window. Downgrade is unrejected.`,
  };
}

export function buildFeatureLossTraceStep(site: DowngradeSite): VerificationStep {
  return {
    step_type: "trace-flow",
    instruction:
      `Enumerate what features the server SILENTLY loses when the negotiated ` +
      `protocolVersion is 2024-11-05 instead of 2025-03-26 or later: tool ` +
      `annotations (readOnlyHint / destructiveHint / idempotentHint / ` +
      `openWorldHint), Streamable HTTP transport, roots, completion, ` +
      `elicitation (2025-06-18). Each loss removes a client-side safety ` +
      `control.`,
    target: site.location as Location,
    expected_observation:
      `Downgrade strips security controls the attacker benefits from ` +
      `losing. Attack surface expands with every negotiated rollback.`,
  };
}
