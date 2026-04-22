/**
 * O10 verification-step builders.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { TelemetrySite } from "./gather.js";

export function stepInspectSurfaceEnumeration(
  site: TelemetrySite,
): VerificationStep {
  const target: Location =
    site.surfaces[0]?.location ?? site.networkSink.location;
  const kinds = Array.from(new Set(site.surfaces.map((s) => s.kind))).join(", ");
  return {
    step_type: "inspect-source",
    instruction:
      `Open the source at the reported location and confirm the tool ` +
      `enumerates host identity surfaces (${kinds}). A legitimate ` +
      `server reads one or two surfaces strictly needed for its stated ` +
      `purpose (e.g. path separator selection). A telemetry harvester ` +
      `reads several at once and bundles them.`,
    target,
    expected_observation:
      `Observed surface tokens: ${site.surfaces.slice(0, 5).map((s) => s.token).join(", ")} ` +
      `(${site.surfaces.length} total). These identify the box's OS, ` +
      `hardware, installed software, or device identity.`,
  };
}

export function stepInspectNetworkSink(site: TelemetrySite): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Confirm the enumerated surfaces flow to the network-send primitive ` +
      `"${site.networkSink.token}". A legitimate server keeps telemetry ` +
      `server-local (structured logger) or gates transmission on explicit ` +
      `user opt-in.`,
    target: site.networkSink.location,
    expected_observation:
      site.pixelHint
        ? `A tracking-pixel / analytics hint string ("${site.pixelHint.token}") ` +
          `is embedded in the same function — the surfaces flow out via ` +
          `an HTML / response-body channel rather than a direct POST.`
        : `The surfaces reach a ${site.networkSink.token} call in the same ` +
          `enclosing function — transmission off-box is structurally proven.`,
  };
}

export function stepCheckConsentGate(site: TelemetrySite): VerificationStep {
  const target: Location =
    site.enclosingFunctionLocation ?? site.networkSink.location;
  return {
    step_type: "check-config",
    instruction:
      `Walk the enclosing function and verify whether transmission is ` +
      `gated on a consent / opt-in flag. Legitimate opt-in telemetry ` +
      `checks an identifier like telemetryEnabled / consent / optIn / ` +
      `allowTelemetry before sending.`,
    target,
    expected_observation:
      site.consentFlag
        ? `Consent identifier "${site.consentFlag}" observed in an enclosing ` +
          `if-predicate. The finding is demoted but not suppressed — confirm ` +
          `the predicate is honoured on every path.`
        : `No consent / opt-in predicate in scope. Transmission is ` +
          `unconditional — the hallmark of background telemetry.`,
  };
}
