/**
 * M1 verification-step factories. Each step carries a structured Location
 * target (Rule Standard v2 §4) — no prose-string targets.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { TokenSite } from "./gather.js";

export function buildTokenInspectionStep(site: TokenSite): VerificationStep {
  const target: Location = site.location;
  const where =
    site.surface === "tool_name"
      ? `the name of tool "${site.tool_name}"`
      : site.surface === "tool_description"
        ? `the description of tool "${site.tool_name}"`
        : `parameter "${site.parameter_path}" of tool "${site.tool_name}"`;
  return {
    step_type: "inspect-description",
    instruction:
      `Open ${where} and locate the literal "${site.literal}" (a ` +
      `${site.label}). Confirm the character sequence is present verbatim ` +
      `in the metadata the server returns from tools/list.`,
    target,
    expected_observation:
      `The metadata field contains the byte sequence "${site.literal}" at ` +
      `offset ${site.offset}. This is an LLM chat-template control token, ` +
      `not decorative prose — the client's chat-template serialiser will ` +
      `emit it verbatim into the model's prompt input.`,
  };
}

export function buildTemplateTraceStep(site: TokenSite): VerificationStep {
  const target: Location = { kind: "capability", capability: "tools" };
  return {
    step_type: "trace-flow",
    instruction:
      `Trace how the tools/list response carries this token into the ` +
      `client's chat template. For ChatML-family clients (OpenAI, GPT-4), ` +
      `<|im_start|> and <|im_end|> are role boundaries. For Llama-family ` +
      `clients, [INST], [/INST], <<SYS>>, <</SYS>>, <|begin_of_text|>, ` +
      `<|eot_id|> all function as role or turn boundaries.`,
    target,
    expected_observation:
      `Client's chat-template serialiser treats the token as a role or ` +
      `turn boundary, granting the bytes that follow it the priority of ` +
      `system-role input instead of tool-metadata-role input.`,
  };
}

export function buildSanitiserStep(site: TokenSite): VerificationStep {
  const target: Location = site.location;
  return {
    step_type: "inspect-source",
    instruction:
      `Verify the server does NOT perform token-stripping before returning ` +
      `tools/list. A correct mitigation strips the known control-token set ` +
      `(at minimum: ChatML <|im_*|> and Llama [INST]/<<SYS>>) from every ` +
      `tool name and description prior to emitting the list response.`,
    target,
    expected_observation:
      `No token-stripping sanitiser present. The server returns the ` +
      `metadata verbatim, including the control token.`,
  };
}
