import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { SmuggleSite } from "./gather.js";

export function buildSmuggleInspectionStep(site: SmuggleSite): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open line ${site.line}. The ${site.smuggle_label} construction is ` +
      `a known HTTP-desync vector.`,
    target: site.location as Location,
    expected_observation: `Line reads: "${site.line_text}".`,
  };
}

export function buildDualHeaderStep(site: SmuggleSite): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Within the same handler, look for BOTH Transfer-Encoding: chunked ` +
      `and Content-Length being set. Two parsers (intermediary vs. backend) ` +
      `will disagree on which to honour — this is the desync vector.`,
    target: site.location as Location,
    expected_observation:
      site.dual_headers
        ? `Both headers present in proximity. Desync is likely exploitable.`
        : `Not obviously dual-headered. Still review — raw chunked framing ` +
          `or chunk-extension abuse is independently sufficient.`,
  };
}

export function buildSmuggleFlowStep(site: SmuggleSite): VerificationStep {
  return {
    step_type: "trace-flow",
    instruction:
      `Trace the desync: attacker positions the intermediary at one ` +
      `boundary and the backend at another, then smuggles a second JSON-RPC ` +
      `request into the victim's session. Impact extends beyond the single ` +
      `connection.`,
    target: site.location as Location,
    expected_observation:
      `Smuggled second request arrives at the MCP server identified as ` +
      `the victim's session, executing attacker intent under the victim's ` +
      `identity.`,
  };
}
