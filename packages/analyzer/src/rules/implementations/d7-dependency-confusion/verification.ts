import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { ConfusionSite } from "./gather.js";

export function stepCheckPublicRegistry(site: ConfusionSite): VerificationStep {
  return {
    step_type: "compare-baseline",
    instruction:
      `Open the npm public-registry page for ${site.name} at https://www.npmjs.com/package/${site.name}. ` +
      `Compare publisher identity, publish date, download count, and postinstall scripts against the ` +
      `expected private package. A typical Birsan-style impostor presents: recently published, low ` +
      `download count, no linked repository, suspicious postinstall hook.`,
    target: site.dependencyLocation,
    expected_observation:
      `Either the public registry record matches the intended private publisher (add to a local ` +
      `allowlist), or the record is clearly impostor-shaped (different publisher, recent publish, low ` +
      `downloads).`,
  };
}

export function stepInspectRegistryPin(site: ConfusionSite): VerificationStep {
  const npmrcLocation: Location = {
    kind: "config",
    file: ".npmrc",
    json_pointer: `/${site.scope}:registry`,
  };
  return {
    step_type: "check-config",
    instruction:
      `Open \`.npmrc\` (or the equivalent pip.conf for Python scopes) and confirm that ` +
      `\`${site.scope}:registry=<private-url>\` is set to the private registry. Without the pin, ` +
      `npm resolves ${site.name} from the PUBLIC registry first — the core condition Birsan's ` +
      `technique exploits.`,
    target: npmrcLocation,
    expected_observation:
      `\`.npmrc\` contains \`${site.scope}:registry=https://<private-registry>\` pinning resolution ` +
      `to the private registry. If this line is missing, the project is vulnerable.`,
  };
}

export function stepInspectManifest(site: ConfusionSite): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Open the manifest and confirm ${site.name}@${site.version} is the version the project ` +
      `intended. The major version ${site.major} is suspiciously high — verify whether this is ` +
      `an intentional internal pin or whether npm resolved the public impostor.`,
    target: site.configLocation,
    expected_observation:
      `Manifest lists ${site.name} at version ${site.version}. Provenance: either confirmed private ` +
      `(legitimate) or confirmed public impostor (remove + audit build environment).`,
  };
}
