import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { Mismatch } from "./gather.js";

export function buildDeclarationInspectionStep(m: Mismatch): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Open the capabilities declaration at line ${m.declaration.line} ` +
      `and confirm "${m.capability_key}" is ${m.declaration.downgrade_label}.`,
    target: m.declaration.location as Location,
    expected_observation:
      `Line reads: "${m.declaration.line_text}".`,
  };
}

export function buildHandlerInspectionStep(m: Mismatch): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open line ${m.handler.line} and confirm a handler is registered for ` +
      `the spec method "${m.handler.method}" (capability "${m.capability_key}"). ` +
      `This contradicts the capabilities declaration.`,
    target: m.handler.location as Location,
    expected_observation: `Line reads: "${m.handler.line_text}".`,
  };
}

export function buildDeceptionImpactStep(m: Mismatch): VerificationStep {
  return {
    step_type: "trace-flow",
    instruction:
      `Verify the consequence: the client that reads the declaration will ` +
      `not apply ${m.capability_key}-scoped consent prompts or audit ` +
      `logging, but the server will still dispatch to the handler when the ` +
      `method is called.`,
    target: {
      kind: "capability",
      capability: m.capability_key as
        | "tools"
        | "resources"
        | "prompts"
        | "sampling"
        | "logging",
    },
    expected_observation:
      `Client-side security controls for ${m.capability_key} are disarmed ` +
      `while server-side execution proceeds.`,
  };
}
