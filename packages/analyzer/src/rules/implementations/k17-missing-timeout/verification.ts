/**
 * K17 verification-step builders — every step carries a structured Location.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { HttpCallSite, FileEvidence, K17Gathered } from "./gather.js";

export function stepInspectCall(site: HttpCallSite): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the file at this line. Confirm \`${site.clientLabel}(...)\` is ` +
      `called with NO timeout-shaped option in its argument list (checked ` +
      `properties: timeout, signal, deadline, headersTimeout, bodyTimeout, ` +
      `requestTimeout, responseTimeout, connectTimeout) AND no AbortSignal ` +
      `reference in an enclosing function / source-file scope.`,
    target: site.location,
    expected_observation:
      `A call to ${site.clientLabel} on the normal control-flow path with ` +
      `no visible timeout.`,
  };
}

export function stepCheckGlobalTimeout(
  file: FileEvidence,
  location: Location,
): VerificationStep {
  const summary = [
    file.hasGlobalAxiosTimeout ? "axios: global timeout present" : "axios: none",
    file.hasGlobalGotTimeout ? "got: factory timeout present" : "got: none",
    file.hasGlobalKyTimeout ? "ky: factory timeout present" : "ky: none",
  ].join("; ");
  return {
    step_type: "inspect-source",
    instruction:
      `Search the file for \`axios.defaults.timeout = ...\`, ` +
      `\`axios.create({ timeout: ... })\`, \`got.extend({ timeout: ... })\`, ` +
      `\`ky.create({ timeout: ... })\`. If any exists, verify the current ` +
      `call uses the same client instance — an axios timeout only covers ` +
      `axios calls, not fetch or got.`,
    target: location,
    expected_observation: `Observed globals — ${summary}.`,
  };
}

export function stepCheckCircuitBreaker(gathered: K17Gathered): VerificationStep {
  const location: Location = {
    kind: "config",
    file: "package.json",
    json_pointer: "/dependencies",
  };
  return {
    step_type: "check-dependency",
    instruction: gathered.hasCircuitBreakerDep
      ? `A circuit-breaker library (${gathered.circuitBreakerName}) is ` +
        `installed. Verify that every HTTP call reaches an upstream through ` +
        `the breaker wrapper; raw calls that bypass the breaker still fail K17.`
      : `Open package.json and confirm NO circuit-breaker library (opossum, ` +
        `cockatiel, brakes, levee, hystrixjs) is installed. Combined with a ` +
        `missing per-call timeout, this elevates the DoS exposure.`,
    target: location,
    expected_observation: gathered.hasCircuitBreakerDep
      ? `Circuit-breaker package ${gathered.circuitBreakerName} listed in dependencies.`
      : `No circuit-breaker package in dependencies.`,
  };
}
