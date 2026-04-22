/**
 * L5 verification-step builders. Each VerificationStep.target is a
 * structured Location so an auditor can jump straight to the file
 * position under review.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { L5Context, L5Primitive } from "./gather.js";

/** Step 1 — inspect the manifest context (file root or AST literal). */
export function stepInspectManifestContext(ctx: L5Context): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction: ctx.fromPackageJsonFile
      ? `Open the package.json at this path and confirm the manifest shape: it ` +
        `must be the root package manifest (not a nested node_modules/** copy) ` +
        `AND it must contain the scripts / bin / exports field this finding ` +
        `references. Sub-manifests inside node_modules are not L5 targets.`
      : `Open the source file at this position and confirm the object literal ` +
        `IS a package-manifest payload (has scripts / bin / exports top-level ` +
        `keys). Embedded manifest literals are found in CI scripts that ` +
        `generate package.json at build time — that generation is a supply-` +
        `chain primitive just as much as a committed manifest.`,
    target: ctx.manifestLocation,
    expected_observation: ctx.fromPackageJsonFile
      ? `The package.json file renders the manifest primitive named in the finding.`
      : `An object-literal with scripts / bin / exports that carries the primitive.`,
  };
}

/** Step 2 — inspect the specific primitive site. */
export function stepInspectPrimitive(primitive: L5Primitive): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Examine the ${primitiveLabel(primitive)} at this position. ${primitive.detail}`,
    target: primitive.location,
    expected_observation: primitive.observed,
  };
}

/** Step 3 — check for publisher integrity mitigations. */
export function stepCheckProvenance(ctx: L5Context): VerificationStep {
  const target: Location = ctx.fromPackageJsonFile
    ? ctx.manifestLocation
    : { kind: "config", file: "package.json", json_pointer: "/publishConfig" };
  return {
    step_type: "check-config",
    instruction: ctx.hasProvenanceField
      ? `publishConfig.provenance is set. Confirm that the package is in fact ` +
        `published with \`npm publish --provenance\` (Sigstore attestation). ` +
        `Provenance binds the build source to the tarball — it does NOT bind ` +
        `the registry manifest view to the tarball manifest, so it mitigates ` +
        `but does not eliminate L5.`
      : `Confirm there is no publishConfig.provenance field and no ` +
        `.npm-provenance.json alongside the manifest. Absence means publishers ` +
        `can serve divergent manifest views between the registry and the ` +
        `tarball without cryptographic contradiction.`,
    target,
    expected_observation: ctx.hasProvenanceField
      ? `publishConfig.provenance: true observed — mitigation partial.`
      : `No Sigstore provenance — the primitive lands unverified.`,
  };
}

function primitiveLabel(p: L5Primitive): string {
  switch (p.kind) {
    case "prepublish-manifest-mutation":
      return "publish-lifecycle script that mutates package.json";
    case "bin-system-shadow":
      return "bin entry shadowing a system command";
    case "bin-hidden-target":
      return "bin entry pointing at a hidden file";
    case "exports-divergence":
      return "conditional exports divergence with a payload-shaped filename";
    case "exports-package-json-block":
      return "exports map blocking audit access to package.json";
  }
}
