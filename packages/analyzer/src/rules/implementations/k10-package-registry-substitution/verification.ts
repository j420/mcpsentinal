/**
 * K10 verification-step builders. Every VerificationStep.target is a
 * structured Location.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { K10Fact } from "./gather.js";

/** Step 1 — inspect the registry URL in its config-file context. */
export function stepInspectRegistryUrl(fact: K10Fact): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open this configuration line and verify the URL "${fact.url}" is intended. ` +
      `Check: (1) Is this a known enterprise registry (Artifactory / Nexus / ` +
      `Verdaccio / JFrog / private.<corp>) or an unknown external host? ` +
      `(2) Is the URL HTTPS — not plain HTTP? (3) Is a scope limiter present ` +
      `(@scope:registry=…) so this URL applies only to a package namespace, ` +
      `not globally? (4) Is the value set here committed to source, or is it ` +
      `only injected at runtime via an environment variable?`,
    target: fact.location,
    expected_observation: `A ${fact.classification} registry URL for ${fact.ecosystem}.`,
  };
}

/** Step 2 — check integrity mitigation. */
export function stepCheckIntegrity(fact: K10Fact): VerificationStep {
  const target: Location = fact.integrityHashPresent
    ? { kind: "config", file: "package-lock.json", json_pointer: "/" }
    : fact.location;
  return {
    step_type: "check-dependency",
    instruction: fact.integrityHashPresent
      ? `An integrity-hash mechanism (package-lock.json with integrity fields, ` +
        `go.sum, yarn.lock integrity, or pip require-hashes) is configured. ` +
        `Confirm the lockfile is COMMITTED and is generated from a trusted ` +
        `registry resolution. Integrity hashes protect against version swap ` +
        `AFTER the lockfile is pinned, but the FIRST resolution from an ` +
        `untrusted registry still loads whatever that registry served.`
      : `No integrity-hash mechanism observed. Without pinned hashes the ` +
        `package manager accepts whatever the (potentially untrusted) ` +
        `registry returns on every install. Enable npm's integrity field / ` +
        `pip's --require-hashes / go.sum.`,
    target,
    expected_observation: fact.integrityHashPresent
      ? `A lockfile with integrity hashes is present.`
      : `No integrity enforcement — the registry is the sole source of truth.`,
  };
}

/** Step 3 — check for a global vs scoped registry assignment. */
export function stepCheckScopePrecedence(fact: K10Fact): VerificationStep {
  return {
    step_type: "check-config",
    instruction: fact.scoped
      ? `The registry URL is scoped (@scope:registry=…). Confirm the scope ` +
        `restricts the URL to a single package namespace — scoped registries ` +
        `do NOT affect global package resolution. Also verify there is no ` +
        `separate unscoped registry= line below this one that overrides the ` +
        `global behaviour.`
      : `The registry URL is global (no @scope: prefix). Every package ` +
        `resolution passes through this URL — including npm's own helpers ` +
        `and transitive dependencies. Confirm this is intentional and that ` +
        `no narrower scoped line is required instead.`,
    target: fact.location,
    expected_observation: fact.scoped
      ? `A scope-prefixed registry assignment limited to one package namespace.`
      : `An unscoped (global) registry assignment that affects all package resolution.`,
  };
}
