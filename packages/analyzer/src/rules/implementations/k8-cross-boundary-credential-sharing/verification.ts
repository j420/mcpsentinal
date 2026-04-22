/**
 * K8 verification steps — every target carries a structured Location.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { K8Fact } from "./gather.js";

export function stepsForFact(fact: K8Fact): VerificationStep[] {
  return [
    inspectSink(fact),
    traceFromSource(fact),
    checkTokenExchangePolicy(fact),
  ];
}

function inspectSink(fact: K8Fact): VerificationStep {
  switch (fact.kind) {
    case "header-forward":
      return {
        step_type: "inspect-source",
        instruction:
          `Open this outbound call. Confirm the Authorization / X-API-Key ` +
          `/ Cookie header is set to the credential-named identifier ` +
          `(${fact.credentialIdentifier}).`,
        target: fact.location,
        expected_observation:
          `A \`${fact.calleeName}(...)\` call whose options include ` +
          `\`headers: { Authorization: ${fact.credentialIdentifier} }\`.`,
      };
    case "shared-store-write":
      return {
        step_type: "inspect-source",
        instruction:
          `Open this shared-store write. Confirm the value being ` +
          `published contains a credential-named identifier ` +
          `(${fact.credentialIdentifier}).`,
        target: fact.location,
        expected_observation:
          `A \`${fact.calleeName}(...)\` call whose arguments include ` +
          `${fact.credentialIdentifier}.`,
      };
    case "exec-with-credential":
      return {
        step_type: "inspect-source",
        instruction:
          `Open this child-process exec. Confirm the credential ` +
          `(${fact.credentialIdentifier}) is passed in argv / stdin / env.`,
        target: fact.location,
        expected_observation:
          `A \`${fact.calleeName}(...)\` invocation carrying ` +
          `${fact.credentialIdentifier} as part of its argv / env / input.`,
      };
  }
}

function traceFromSource(fact: K8Fact): VerificationStep {
  return {
    step_type: "trace-flow",
    instruction:
      `Trace "${fact.credentialIdentifier}" from its first assignment ` +
      `backward. Identify the trust boundary the credential ORIGINATED ` +
      `inside and confirm the sink at ${fact.file}:${renderLine(fact)} ` +
      `is OUTSIDE that boundary.`,
    target: fact.location,
    expected_observation:
      `The credential was produced for one audience and is now being ` +
      `shared with a different audience.`,
  };
}

function checkTokenExchangePolicy(fact: K8Fact): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Open package.json / mcp.json / docs/security.md. Confirm whether ` +
      `the project documents RFC 8693 Token Exchange as its cross-boundary ` +
      `auth policy.`,
    target: {
      kind: "config",
      file: "package.json",
      json_pointer: "/mcp/auth/token_exchange",
    },
    expected_observation: fact.hasTokenExchange
      ? `A token-exchange primitive is referenced in the source but the ` +
        `flagged call may bypass it.`
      : `No token-exchange primitive observed in the source.`,
  };
}

function renderLine(fact: K8Fact): string {
  if (fact.location.kind === "source") {
    return `${fact.location.line}${fact.location.col !== undefined ? `:${fact.location.col}` : ""}`;
  }
  return "";
}
