/**
 * K14 verification steps. Every target is a structured Location.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { CredentialPropagationSite } from "./gather.js";

export function stepInspectCredentialSource(
  site: CredentialPropagationSite,
): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the credential binding and confirm that the value carries ` +
      `bearer authority — an OAuth access token, an API key, a session ` +
      `cookie, or a derived secret. Identifier name observed: ` +
      `\`${site.credentialName}\`. If the binding is in fact a non-secret ` +
      `(a user id, a request id, an opaque correlation token), classify ` +
      `as a false positive and add a comment.`,
    target: site.credentialSourceLocation,
    expected_observation:
      `A binding whose value semantically authorises calls on behalf of ` +
      `the user or another agent.`,
  };
}

export function stepInspectSharedStateSink(
  site: CredentialPropagationSite,
): VerificationStep {
  return {
    step_type: "trace-flow",
    instruction:
      `Open the shared-state writer call and confirm the receiver ` +
      `\`${site.receiverName}.${site.writerMethod}(...)\` is read by ` +
      `another agent. Pure per-agent caches (the same agent reading ` +
      `back its own write) are not in scope; cross-agent vector stores, ` +
      `LangGraph scratchpads, and AutoGen working-memory tables are. ` +
      `The call kind classified as \`${site.kind}\`.`,
    target: site.location,
    expected_observation:
      `A call placing the credential into a state surface that any ` +
      `downstream agent will read.`,
  };
}

export function stepCheckRedactor(
  site: CredentialPropagationSite,
): VerificationStep {
  const target: Location = site.enclosingFunctionLocation ?? site.location;
  return {
    step_type: "inspect-source",
    instruction: site.enclosingHasRedactor
      ? `A redactor call (redact / mask / scrub / vault.seal / kms.encrypt) ` +
        `was observed in the enclosing function scope. Confirm it acts on ` +
        `the credential bound to \`${site.credentialName}\` and not on a ` +
        `different value — sanitising one variable is not a mitigation ` +
        `for another.`
      : `Confirm the enclosing function body contains no redactor call. ` +
        `Vocabulary inspected: redact / mask / scrub / sanitizecredentials / ` +
        `vault.seal / kms.encrypt / cipher.encrypt. Absence is the ` +
        `compliance gap this rule names.`,
    target,
    expected_observation: site.enclosingHasRedactor
      ? `Redactor observed but its applicability to the credential ` +
        `requires manual confirmation.`
      : `No redactor in enclosing scope — credential is written in the ` +
        `clear to a cross-agent surface.`,
  };
}
