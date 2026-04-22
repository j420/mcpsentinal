import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { TofuSite } from "./gather.js";

export function buildSiteInspectionStep(site: TofuSite): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open line ${site.line}. The code contains ${site.fragment_label} — a ` +
      `TOFU-bypass-class anti-pattern (${site.variant.replace("_", "-")}).`,
    target: site.location as Location,
    expected_observation: `Line reads: "${site.line_text}".`,
  };
}

export function buildBypassImpactStep(site: TofuSite): VerificationStep {
  return {
    step_type: "trace-flow",
    instruction:
      site.variant === "pinning_bypass"
        ? `Trace: with pinning bypassed, a network attacker who swaps server ` +
          `identity between any two connects is accepted as the original ` +
          `server. Every subsequent tool/resource response is attacker-` +
          `controlled.`
        : `Trace: with accept-any-first-connect, an attacker positioned at ` +
          `the first connect plants their own identity in the pin store. ` +
          `All later "verification" succeeds against the attacker.`,
    target: site.location as Location,
    expected_observation:
      `Server identity swap is invisible to the agent; compromise persists ` +
      `for the lifetime of the pin.`,
  };
}

export function buildRemediationStep(site: TofuSite): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Replace TOFU with an out-of-band key-distribution channel: a ` +
      `pre-shared fingerprint, a manual operator confirmation, a CA-signed ` +
      `certificate, or a registry-delivered signed manifest. If TOFU is ` +
      `unavoidable, pin on the FIRST connect with an explicit operator ` +
      `prompt and REJECT subsequent mismatches instead of re-pinning.`,
    target: site.location as Location,
    expected_observation:
      `Trust boundary is established before the first connect, not during ` +
      `it.`,
  };
}
