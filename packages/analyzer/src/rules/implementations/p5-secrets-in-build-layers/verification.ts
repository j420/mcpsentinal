/**
 * P5 verification-step builders.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { P5Hit } from "./gather.js";

export function stepInspectDockerfileLine(hit: P5Hit): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open ${hit.file} at line ${hit.line}. The ${hit.variant.toUpperCase()} ` +
      `directive carries a credential identifier "${hit.credentialName}". Extract ` +
      `the value by running \`docker history --no-trunc <image>\` on any tag ` +
      `built from this Dockerfile. For COPY of .env / credentials files, extract ` +
      `via \`docker save\` + \`tar -x\` — both confirm the credential persistence.`,
    target: hit.location,
    expected_observation: `${hit.variant.toUpperCase()} ${hit.credentialName} — credential persists in image layer.`,
  };
}

export function stepRecordConfigPointer(hit: P5Hit): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Record the config json_pointer for the compliance bundle. Cross-reference ` +
      `CWE-538 (Insertion of Sensitive Information into Externally-Accessible ` +
      `File) and the Docker BuildKit secrets documentation. The remediation is ` +
      `structural: migrate to \`RUN --mount=type=secret,id=<name>\` and delete ` +
      `the ARG / ENV / COPY.`,
    target: hit.configLocation,
    expected_observation: `Config pointer identifies the Dockerfile ${hit.variant} site.`,
  };
}

export function stepCheckBuildKitMigration(hit: P5Hit): VerificationStep {
  const target: Location = {
    kind: "config",
    file: hit.file,
    json_pointer: "/docker/buildkit-usage",
  };
  return {
    step_type: "check-config",
    instruction:
      `Check whether the Dockerfile already uses BuildKit secret mounts elsewhere. ` +
      `If YES, migrating the flagged ${hit.variant} site to the same pattern is ` +
      `a low-friction fix. If NO, enable BuildKit (\`DOCKER_BUILDKIT=1\` or ` +
      `\`# syntax=docker/dockerfile:1.4\`) before migrating.`,
    target,
    expected_observation: hit.buildkitSecretNearby
      ? `Dockerfile already uses BuildKit secret mounts — migration is incremental.`
      : `Dockerfile does not use BuildKit — enable BuildKit first, then migrate.`,
  };
}

export function stepCheckDockerignore(hit: P5Hit): VerificationStep {
  const target: Location = {
    kind: "config",
    file: hit.file,
    json_pointer: "/docker/dockerignore-audit",
  };
  return {
    step_type: "check-config",
    instruction:
      `For COPY / ADD variants, audit the .dockerignore alongside the Dockerfile. ` +
      `A .dockerignore that omits .env / credentials / .npmrc / id_rsa / .git/config ` +
      `entries leaks those files into the build context even when the Dockerfile ` +
      `does not explicitly COPY them. Add each credential-adjacent pattern to ` +
      `.dockerignore in the same change.`,
    target,
    expected_observation: `Operator confirms .dockerignore excludes credential-bearing files.`,
  };
}
