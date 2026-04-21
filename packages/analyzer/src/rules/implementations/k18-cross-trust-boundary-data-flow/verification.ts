import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { CrossBoundaryFlow } from "./gather.js";

export function stepInspectSource(flow: CrossBoundaryFlow): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the sensitive source. The rule classifies it as ` +
      `\`${flow.source.kind}\` ` +
      (flow.source.kind === "sensitive-param"
        ? `(based on parameter name tokens only — softer evidence).`
        : `(concrete env / credential / sensitive-path signal).`),
    target: flow.source.location,
    expected_observation:
      `Sensitive value at \`${flow.source.kind}\` location flows toward a ` +
      `cross-trust-boundary sink.`,
  };
}

export function stepInspectSink(flow: CrossBoundaryFlow): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      flow.sinkKind === "return-statement"
        ? `Open the ReturnStatement. Confirm the returned expression carries ` +
          `the tainted value. The AI client receives the value in its context ` +
          `window, may echo it in subsequent turns, and any downstream log / ` +
          `tool consuming the response exposes the secret at its own layer.`
        : flow.sinkKind === "response-call"
          ? `Open the response-emitting call (res.send / res.json / ctx.body). ` +
            `Confirm the argument carries the tainted value. The transmitted ` +
            `payload crosses the server → client trust boundary with the ` +
            `secret embedded.`
          : `Open the network-send call. Confirm the outbound request body ` +
            `carries the tainted value. The secret leaves the server process ` +
            `in plaintext.`,
    target: flow.sinkLocation,
    expected_observation:
      `${flow.sinkKind} carries sensitive content across the trust boundary.`,
  };
}

export function stepInspectRedactor(flow: CrossBoundaryFlow): VerificationStep {
  const target: Location = flow.enclosingFunctionLocation ?? flow.sinkLocation;
  const { present, sameVariable, detail } = flow.redactor;
  return {
    step_type: "inspect-source",
    instruction: present
      ? sameVariable
        ? `A redactor was observed AND applied to the tainted identifier. ` +
          `If the finding fired anyway, applicability must be manually ` +
          `confirmed. Detail: ${detail}`
        : `A redactor was observed in scope but not on the tainted ` +
          `identifier. The compliance gap stands. Detail: ${detail}`
      : `Walk the enclosing function body and confirm that NO redactor ` +
        `(redact / mask / strip / omit / sanitize / encrypt / scrub / ` +
        `censor / obfuscate, or redactor.* / privacy.* / security.*) ` +
        `operates on the tainted identifier. Absence is the ISO 27001 ` +
        `A.5.14 control gap.`,
    target,
    expected_observation: present
      ? `Redactor observed but not applicable to the tainted value.`
      : `No redactor in the enclosing function — sensitive data crosses the ` +
        `trust boundary unredacted.`,
  };
}
