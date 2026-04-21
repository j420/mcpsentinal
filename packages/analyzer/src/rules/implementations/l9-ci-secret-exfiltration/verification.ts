/**
 * L9 verification-step builders. Each step carries a structured
 * `target: Location` (v2 standard §4). The steps collectively form the
 * reproduction path an auditor follows to confirm the finding.
 *
 * Zero regex, zero long string arrays.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { ExfilFact, SecretSource } from "./gather.js";

export function stepInspectEnvSource(secret: SecretSource): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      secret.bulk
        ? `Open the file at this position and confirm the expression serialises the WHOLE ` +
          `environment (process.env / os.environ). The bulk-dump shape (${secret.bulkShape?.callee}) ` +
          `captures every injected CI secret simultaneously.`
        : `Open the file at this position and confirm the expression reads the env variable \`${secret.envName}\`. ` +
          `Cross-reference with the CI workflow definition: is this variable actually set from a real secret ` +
          `(GitHub ` + `secrets / GitLab masked vars / CircleCI contexts), or is it an unset placeholder?`,
    target: secret.location,
    expected_observation:
      secret.bulk
        ? `Bulk-env read: ${secret.bulkShape?.description}.`
        : `Env read of \`${secret.envName}\` — matched credential markers: ${secret.markers.map((m) => m.token).join(", ")}.`,
  };
}

export function stepInspectExfilSink(fact: ExfilFact): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the file at this position and confirm the call is \`${fact.sink.name}\` and one of its ` +
      `arguments (or an argument-subtree — template literal, object property, wrapper call) references ` +
      `the secret from the previous step. The ${fact.sink.channel} channel is the exfil egress: ` +
      `${fact.sink.rationale}. Safe equivalents (a static hardcoded body, a non-sensitive telemetry ` +
      `field) would have caused the gather step to skip this call.`,
    target: fact.sinkLocation,
    expected_observation:
      `A \`${fact.sink.name}\` call whose argument subtree contains a reference to the secret ` +
      `\`${fact.secret.envName}\`${fact.propagation.length > 0 ? ` (reached via ${fact.propagation.length} propagation hop(s))` : ""}.`,
  };
}

export function stepTracePropagation(fact: ExfilFact): VerificationStep {
  if (fact.propagation.length === 0) {
    return {
      step_type: "trace-flow",
      instruction:
        `The secret is referenced directly inside the sink call — zero propagation hops. Confirm there ` +
        `is no intermediate variable / wrapper / encoding step the AST walker missed (e.g. indirect access ` +
        `through a dynamic property name or a numeric index into a serialised buffer).`,
      target: fact.sinkLocation,
      expected_observation:
        `Direct reference — the secret appears verbatim inside the sink call argument subtree.`,
    };
  }
  const first = fact.propagation[0];
  const rendered = fact.propagation
    .map((p) => `${p.kind}@${renderLoc(p.location)} (${p.observed.slice(0, 60)})`)
    .join(" → ");
  return {
    step_type: "trace-flow",
    instruction:
      `Walk the following ${fact.propagation.length} propagation hop(s) in order and confirm each is a ` +
      `real data-flow step: ${rendered}. A broken hop invalidates the chain.`,
    target: first.location,
    expected_observation:
      `The secret flows through ${fact.propagation.length} hop(s) — alias-binding / template-embed / ` +
      `wrapper-call / spread — before reaching the sink.`,
  };
}

export function stepInspectMitigation(fact: ExfilFact): VerificationStep | null {
  if (!fact.mitigation || !fact.mitigationLocation) return null;
  return {
    step_type: "inspect-source",
    instruction:
      `A charter-audited masking primitive \`${fact.mitigation.name}\` (${fact.mitigation.description}) ` +
      `was observed in the enclosing function scope. Confirm the binding resolves to the real masking API ` +
      `and not a shadowed identifier that re-exports a no-op — an override that imports \`${fact.mitigation.name}\` ` +
      `but re-exports a pass-through still satisfies the name-only check here.`,
    target: fact.mitigationLocation,
    expected_observation:
      `A call to \`${fact.mitigation.name}\` in the same function scope as the sink. If the binding is ` +
      `charter-known, log exposure is neutralised; network / file-write channels still require remediation.`,
  };
}

export function stepCheckCiSecretMasking(): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      "Open the CI workflow definition (.github/workflows/*.yml, .gitlab-ci.yml, .circleci/config.yml) " +
      "and confirm no step calls `::add-mask::` or `core.setSecret(...)` on the environment variable named " +
      "in the source above. If masking IS configured, log exfil is partially neutralised but NETWORK exfil " +
      "(fetch / axios / dns.resolve) is not — severity stays critical. Also confirm whether OIDC tokens " +
      "have replaced the long-lived PAT/NPM_TOKEN; a short-lived OIDC token limits the blast radius but " +
      "does not remove the exfil finding.",
    target: {
      kind: "config",
      file: ".github/workflows/<workflow>.yml",
      json_pointer: "/jobs",
    },
    expected_observation:
      "No `::add-mask::` call on the secret-bearing env var; or if present, confirmation that it does not " +
      "cover network / file-write exfil paths.",
  };
}

function renderLoc(loc: Location): string {
  return loc.kind === "source"
    ? `${loc.file}:${loc.line}${loc.col !== undefined ? `:${loc.col}` : ""}`
    : loc.kind;
}
