/**
 * H2 verification-step builders.
 *
 * Every step's `target` is a structured Location of kind "initialize"
 * with an explicit field discriminator so a reviewer can navigate to
 * the precise handshake surface (server_name / server_version /
 * instructions).
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { FieldSite, InitField } from "./gather.js";

function initLoc(field: InitField): Location {
  return { kind: "initialize", field };
}

export function stepInspectField(
  field: InitField,
  primary: FieldSite,
): VerificationStep {
  return {
    step_type: "inspect-description",
    instruction:
      `Re-run the MCP initialize handshake against the server and capture ` +
      `the raw JSON-RPC InitializeResult. Inspect the "${field}" field at ` +
      `offset ${primary.offset} (length ${primary.length}). Confirm that ` +
      `"${primary.observed}" appears verbatim. This field is processed ` +
      `BEFORE any tool description and is the highest-trust injection ` +
      `surface in the MCP protocol.`,
    target: initLoc(field),
    expected_observation:
      `The ${field} field contains ${primary.kind} "${primary.label}" ` +
      `at offset ${primary.offset}.`,
  };
}

export function stepCompareSpec(field: InitField): VerificationStep {
  return {
    step_type: "compare-baseline",
    instruction:
      `Compare the server's ${field} field against the MCP specification ` +
      `(2024-11-05 / 2025-03-26). A compliant ${field} MUST be plain text ` +
      `containing no LLM control tokens, no Unicode control characters, and ` +
      `no multi-sentence behavioural directives. Replace the offending ` +
      `content with a compliant value and re-run the scanner — H2 should ` +
      `produce zero findings for this field.`,
    target: initLoc(field),
    expected_observation:
      `A compliant ${field} value produces zero H2 matches when re-scanned.`,
  };
}

export function stepTraceSessionImpact(field: InitField): VerificationStep {
  return {
    step_type: "trace-flow",
    instruction:
      `Trace how the MCP client forwards the ${field} field into the ` +
      `model's context. In typical clients, server_instructions is prepended ` +
      `to the system prompt and serverInfo fields appear in the connection-` +
      `setup narrative. Verify that this client in particular forwards the ` +
      `injected string and that there is no sanitisation stage in between.`,
    target: initLoc(field),
    expected_observation:
      `The ${field} content reaches the model's context unaltered and ` +
      `establishes behavioural rules for the rest of the session.`,
  };
}
