import type { VerificationStep } from "../../../evidence.js";
import type { SpoofSite } from "./gather.js";

export function stepInspectField(site: SpoofSite): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the file and navigate to the "${site.field}" field. ` +
      `Confirm the vendor attribution "${site.vendor}" is literal (not ` +
      `a legitimate name that happens to contain the vendor token).`,
    target: site.location,
    expected_observation:
      `Field "${site.field}" claims affiliation with "${site.vendor}".`,
  };
}

export function stepCheckPublisher(site: SpoofSite): VerificationStep {
  return {
    step_type: "check-dependency",
    instruction:
      `Run npm view / pip show on "${site.package_name ?? "(this package)"}" ` +
      `and confirm the registered publisher / author matches the "${site.vendor}" ` +
      `organisation. If it does not, this is a spoofed attribution.`,
    target: site.location,
    expected_observation:
      `Registry publisher does NOT match "${site.vendor}".`,
  };
}

export function stepCheckNamespace(site: SpoofSite): VerificationStep {
  return {
    step_type: "check-dependency",
    instruction:
      `Confirm the package namespace does NOT start with "@${site.vendor}/". ` +
      `A scoped package under the vendor's official npm org is a legitimate ` +
      `attestation; this rule already filters those out, so reaching this ` +
      `step means the package is unscoped or under a different org.`,
    target: site.location,
    expected_observation:
      `Package "${site.package_name ?? "<unknown>"}" is NOT scoped under @${site.vendor}/.`,
  };
}
