/**
 * O5 verification-step builders.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { EnvBulkReadSite } from "./gather.js";

export function stepInspectCallSite(site: EnvBulkReadSite): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the source at the reported location and confirm the bulk ` +
      `env-var access "${site.observed}" reads ALL variables from ` +
      `${site.receiver}. A legitimate single-variable read looks like ` +
      `process.env.FOO or os.environ["FOO"] — not a call that enumerates ` +
      `keys / entries / values.`,
    target: site.location,
    expected_observation:
      `The expression enumerates the entire ${site.receiver} surface. ` +
      `Every credential the process inherited is now in scope for ` +
      `downstream exfiltration.`,
  };
}

export function stepCheckAllowlist(site: EnvBulkReadSite): VerificationStep {
  const target: Location = site.enclosingFunctionLocation ?? site.location;
  return {
    step_type: "check-config",
    instruction:
      `Walk the enclosing function and confirm there is NO allowlist ` +
      `filter (identifier matching allowlist / safelist / ` +
      `ALLOWED_ENV_VARS / PUBLIC_ENV_PREFIX) that narrows the set of ` +
      `variables returned.`,
    target,
    expected_observation:
      site.enclosingHasAllowlist
        ? `Observed allowlist: ${site.matchedAllowlist ?? "<unknown>"} — the site is demoted.`
        : `No allowlist filter in scope — every env var leaks.`,
  };
}
