import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { UnsanitizedFlow } from "./gather.js";

export function stepInspectSource(flow: UnsanitizedFlow): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the external-source site. The call is classified as ` +
      `\`${flow.source.kind}\` — the rule records it as an untrusted ` +
      `boundary because the caller cannot control what arrives. A ` +
      `web fetch may return attacker-controlled HTML, a file read ` +
      `may return attacker-controlled content if the path is ` +
      `user-influenced, a database row may carry cross-user content.`,
    target: flow.source.location,
    expected_observation:
      `External read \`${flow.source.kind}\` returning data that ` +
      `flows toward the tool response boundary.`,
  };
}

export function stepInspectResponse(flow: UnsanitizedFlow): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      flow.siteType === "return-statement"
        ? `Open the ReturnStatement. Confirm the returned expression carries ` +
          `the tainted value sourced above. The AI client treats the ` +
          `returned bytes as a trustworthy tool output; an injection ` +
          `payload embedded in the external source reaches the model at ` +
          `the tool-output boundary without any intermediate control.`
        : `Open the response-emitting call (res.send / res.json / ctx.body). ` +
          `Confirm the argument carries the tainted value sourced above. ` +
          `The client treats the emitted bytes as a trustworthy tool output.`,
    target: flow.responseLocation,
    expected_observation:
      `Response path carries external content to the AI client.`,
  };
}

export function stepInspectSanitizer(flow: UnsanitizedFlow): VerificationStep {
  const target: Location = flow.enclosingFunctionLocation ?? flow.responseLocation;
  const { present, sameVariable, detail } = flow.sanitizerApplied;
  return {
    step_type: "inspect-source",
    instruction: present
      ? sameVariable
        ? `A sanitizer call was observed AND applied to the returned ` +
          `identifier — the finding should not fire. If it did, the ` +
          `applicability must be manually reconfirmed. Detail: ${detail}`
        : `A sanitizer call was observed in the enclosing function, but ` +
          `not on the returned identifier. Confirm the returned value ` +
          `is not sanitized. Detail: ${detail}`
      : `Walk the enclosing function body and confirm that NO sanitizer ` +
        `call (sanitize / sanitizeHtml / escapeHtml / DOMPurify.sanitize / ` +
        `he.encode / validator.escape / stripTags / redact) operates on ` +
        `the returned value. Absence is the compliance gap this rule names.`,
    target,
    expected_observation: present
      ? `Sanitizer observed but not applicable to the returned value.`
      : `No sanitizer observed — tool response carries raw external content.`,
  };
}
