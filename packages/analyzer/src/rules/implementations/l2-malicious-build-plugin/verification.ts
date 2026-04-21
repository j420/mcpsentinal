/**
 * L2 — Malicious Build Plugin: verification-step builders.
 *
 * Every target is a structured Location pointing at the exact JSON
 * pointer (install-hook finding) or file:line:col (build-config
 * finding).
 */

import type { VerificationStep } from "../../../evidence.js";
import type { L2Fact } from "./gather.js";

export function stepInspectOffendingSite(fact: L2Fact): VerificationStep {
  switch (fact.kind) {
    case "install-hook-dangerous":
      return {
        step_type: "check-config",
        instruction:
          "Open package.json and navigate to the indicated /scripts/<hook>. " +
          "Confirm the script runs at install time (not only behind an " +
          "environment variable the attacker controls). Even gated hooks " +
          "fire on CI runners that match the gate.",
        target: fact.location,
        expected_observation:
          `Install hook '${fact.hookName}' body contains a fetch-and-exec token. ` +
          `Observed: "${fact.observed.slice(0, 160)}".`,
      };
    case "plugin-hook-dangerous-api":
      return {
        step_type: "inspect-source",
        instruction:
          "Open the build-config file at this line:col. Confirm the " +
          "function literal really runs as a bundler plugin hook — " +
          "Rollup, Vite, webpack, and esbuild invoke these hooks during " +
          "bundling with the node process's full privileges.",
        target: fact.location,
        expected_observation:
          `Plugin hook '${fact.hookName}' invokes ${fact.api?.name ?? "a dangerous API"}: ` +
          `${fact.api?.description ?? fact.description}. ` +
          `Observed: "${fact.observed.slice(0, 160)}".`,
      };
    case "dynamic-plugin-load":
      return {
        step_type: "inspect-source",
        instruction:
          "Open the build config and verify the require/import expression " +
          "at this position resolves to a hard-coded plugin identity. " +
          "A variable argument means the plugin chosen at build time is " +
          "not visible in a static code review.",
        target: fact.location,
        expected_observation:
          `require/import(...) is invoked with a non-literal argument: ` +
          `"${fact.observed.slice(0, 160)}".`,
      };
    case "url-plugin-import":
      return {
        step_type: "inspect-source",
        instruction:
          "Open the build config at this line and confirm the plugin source is " +
          "an HTTP(S) URL. ESM-over-HTTPS imports are not in the project's " +
          "dependency tree and therefore not subject to npm audit, pnpm audit, " +
          "or lockfile integrity checks.",
        target: fact.location,
        expected_observation:
          `import/require from URL: "${fact.observed.slice(0, 160)}".`,
      };
  }
}

export function stepCheckLockfileIntegrity(fact: L2Fact): VerificationStep {
  return {
    step_type: "check-dependency",
    instruction:
      "Open package-lock.json / pnpm-lock.yaml / yarn.lock and confirm that " +
      "the plugin referenced here is present with an integrity hash matching " +
      "the registry. For URL-based imports and dynamic loads, no lockfile " +
      "entry will exist — which IS the finding.",
    target: {
      kind: "config",
      file: "package-lock.json",
      json_pointer: "/packages",
    },
    expected_observation:
      fact.kind === "url-plugin-import" || fact.kind === "dynamic-plugin-load"
        ? "No lockfile entry corresponds to this import — integrity cannot be verified."
        : "Lockfile lists the plugin with a deterministic integrity hash; " +
          "compare the hash against the registry record to confirm no " +
          "substitution occurred.",
  };
}

export function stepInspectCIContext(fact: L2Fact): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      "Open .github/workflows/*.yml (or the equivalent CI pipeline) and " +
      "verify which build / publish job would execute the flagged hook. " +
      "Determine which secrets the job has access to (NPM_TOKEN, " +
      "GITHUB_TOKEN, ANTHROPIC_API_KEY, AWS_*) — those are the secrets a " +
      "successful exfil would steal.",
    target: fact.location,
    expected_observation: fact.readsSensitiveEnv
      ? "The flagged body references process.env (or a sensitive env var). " +
        "Combined with the dangerous API, the payload matches the Shai-Hulud " +
        "worm exfiltration pattern."
      : "No direct sensitive env read observed in scope, but plugin code can " +
        "always read process.env regardless of what the static snippet shows.",
  };
}
