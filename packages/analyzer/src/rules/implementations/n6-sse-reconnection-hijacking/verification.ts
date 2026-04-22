import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { ReconnectSite } from "./gather.js";

export function buildReconnectInspectionStep(site: ReconnectSite): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open line ${site.line} and confirm the ${site.fragment.label} path ` +
      `processes reconnection / resume without authenticating the caller.`,
    target: site.location as Location,
    expected_observation: `Line reads: "${site.line_text}".`,
  };
}

export function buildAuthAbsenceStep(site: ReconnectSite): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Within ±6 lines of line ${site.line}, look for verify / validate / ` +
      `hmac / authenticate / timing-safe. Absence → hijackable.`,
    target: site.location as Location,
    expected_observation:
      site.auth_distance !== null
        ? `Auth fragment "${site.auth_label}" nearby — confirm it actually ` +
          `guards THIS path.`
        : `No auth fragment nearby; reconnection proceeds without identity ` +
          `re-verification.`,
  };
}

export function buildHijackTraceStep(site: ReconnectSite): VerificationStep {
  return {
    step_type: "trace-flow",
    instruction:
      `Trace the effect of a captured Last-Event-ID / session id: the ` +
      `attacker replays the id to resume the victim's stream.`,
    target: site.location as Location,
    expected_observation:
      `Attacker obtains full stream continuity without valid credentials.`,
  };
}
