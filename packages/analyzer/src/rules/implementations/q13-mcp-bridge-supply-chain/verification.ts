/**
 * Q13 verification-step builders.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { BridgeSupplyChainSite } from "./gather.js";

export function stepInspectSite(site: BridgeSupplyChainSite): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the ${site.kind} at the reported Location and confirm the ` +
      `bridge package "${site.packageName}" is invoked without a ` +
      `version pin. A compliant invocation is "${site.packageName}@X.Y.Z" ` +
      `or a lockfile-enforced version.`,
    target: site.location,
    expected_observation:
      `The bridge package is fetched from the registry at runtime ` +
      `without any integrity guarantee. CVE-2025-6514 demonstrated ` +
      `RCE via exactly this flow.`,
  };
}

export function stepPinGuidance(site: BridgeSupplyChainSite): VerificationStep {
  return {
    step_type: "check-dependency",
    instruction:
      `Fix: replace the unpinned invocation with an explicit version ` +
      `(e.g. "${site.packageName}@1.2.3") AND add a lockfile / ` +
      `package-hash check to your deployment pipeline.`,
    target: site.location,
    expected_observation:
      `After pinning + lockfile, the supply-chain surface narrows to ` +
      `exactly the version you audited.`,
  };
}
