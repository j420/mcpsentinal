/**
 * L13 verification steps — every target is a structured Location.
 *
 * Reuses the shared taint-rule-kit's step builders for the full
 * source→sink case; emits dedicated steps for the direct-read and
 * Dockerfile variants.
 */

import type { VerificationStep } from "../../../evidence.js";
import {
  stepInspectTaintSource,
  stepInspectTaintSink,
  stepTraceTaintPath,
} from "../_shared/taint-rule-kit/index.js";
import type { L13Fact } from "./gather.js";

export function stepsForFact(fact: L13Fact): VerificationStep[] {
  if (fact.kind === "taint-cred-to-network" && fact.taintFact) {
    return [
      stepInspectTaintSource(fact.taintFact),
      stepInspectTaintSink(
        fact.taintFact,
        "a network egress call (fetch / axios / got / curl) that carries the credential bytes",
      ),
      stepTraceTaintPath(fact.taintFact),
    ];
  }

  if (fact.kind === "cred-file-read-direct") {
    return [
      {
        step_type: "inspect-source",
        instruction:
          `Open the file at this line:col. Confirm the call reads ` +
          `"${fact.credFile}" at runtime (the argument is not a hard-` +
          `coded non-credential filename that happens to contain the ` +
          `substring). Check whether the containing module is a ` +
          `legitimate CLI configuration setup path (npm login equivalent) ` +
          `or is part of a runtime code path that has no reason to read ` +
          `credentials.`,
        target: fact.location,
        expected_observation:
          `fs read call: "${fact.observed.slice(0, 160)}".`,
      },
      {
        step_type: "trace-flow",
        instruction:
          "Follow the return value of the read call through the module — " +
          "does the content reach fetch / axios / got / stdout / a child " +
          "process stdin? If yes, the finding escalates to a full exfil " +
          "chain (promoted to the taint-cred-to-network family on the next " +
          "scan run). If no, the file-read itself is still a capability " +
          "that should not be in a production code path.",
        target: fact.location,
        expected_observation:
          "No subsequent network / stdout / subprocess send — the read is " +
          "orphaned, which is itself suspicious in production code.",
      },
      {
        step_type: "inspect-source",
        instruction:
          "Check whether the read target is constrained (e.g. only reads " +
          "in a test fixture, only reads under a CI setup flag). Even if " +
          "the read is behind a guard, running on CI means the guard fires " +
          "whenever the repo is built.",
        target: fact.location,
        expected_observation:
          "Either an unconditional read, or a CI-gate-conditional read.",
      },
    ];
  }

  // Dockerfile COPY variant.
  return [
    {
      step_type: "check-config",
      instruction:
        "Open the Dockerfile at the indicated JSON pointer (converted from " +
        "line number). Confirm that the COPY / ADD instruction really " +
        "copies a host credential file into the built image. Anyone who " +
        "pulls the resulting image (including public registries) can " +
        "extract the credential with `docker cp` or by unpacking the layer.",
      target: fact.location,
      expected_observation:
        `${fact.observed.slice(0, 160)} — credential file in image layer`,
    },
    {
      step_type: "check-dependency",
      instruction:
        "Verify whether the image is pushed to a public registry or to a " +
        "private registry. Public registries make the leaked credential " +
        "available to anyone; private registries still carry audit and " +
        "rotation obligations (ISO 27001 A.8.24 cryptographic key lifecycle).",
      target: fact.location,
      expected_observation:
        "Image-push target is identified (Docker Hub / ghcr.io / ECR / " +
        "private Harbor). Credential rotation policy is either enforced " +
        "or absent — if absent, the leak is permanent.",
    },
    {
      step_type: "inspect-source",
      instruction:
        "Replace the COPY with a multi-stage build that uses `--secret` " +
        "mount (BuildKit) so the credential is available at build time " +
        "but is not present in the final image layer.",
      target: fact.location,
      expected_observation:
        "The Dockerfile no longer references the credential file in a COPY " +
        "/ ADD instruction; builds use `--mount=type=secret,id=npmrc` " +
        "instead.",
    },
  ];
}
