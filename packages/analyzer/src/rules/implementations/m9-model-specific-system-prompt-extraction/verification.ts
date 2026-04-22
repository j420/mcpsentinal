import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { LeakSite } from "./gather.js";

export function buildReadSiteStep(site: LeakSite): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open line ${site.line} and confirm the return path reads the ` +
      `${site.prompt_ident.label}. The identifier is named specifically ` +
      `enough that misuse is unlikely.`,
    target: site.location as Location,
    expected_observation:
      `Line reads: "${site.line_text}". A ${site.return_fragment}-shaped ` +
      `construct carries the prompt variable to the tool response.`,
  };
}

export function buildGateCheckStep(site: LeakSite): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Verify whether the return is gated behind a dev / admin / debug ` +
      `check. Absence of a gate within ±${5} lines means the leak path ` +
      `is always reachable.`,
    target: site.location as Location,
    expected_observation:
      site.gate_present
        ? `Gate "${site.gate_label}" found at distance ${site.gate_distance} — ` +
          `verify it actually guards THIS return path.`
        : `No gate keyword within the window. The return path is reachable ` +
          `in all environments.`,
  };
}

export function buildLeakImpactStep(site: LeakSite): VerificationStep {
  return {
    step_type: "trace-flow",
    instruction:
      `Trace from the return at line ${site.line} to any client that can ` +
      `invoke the enclosing tool. Once the prompt escapes, every future ` +
      `session against this server runs with a diminished safety posture ` +
      `because attackers know the exact refusal phrases.`,
    target: site.location as Location,
    expected_observation:
      `Tool caller receives the full system prompt in the response body.`,
  };
}
