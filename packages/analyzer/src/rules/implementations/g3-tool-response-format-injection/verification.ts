/**
 * G3 verification-step builders — every step's target is a
 * structured `tool` Location.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { MimicSite } from "./gather.js";

function loc(tool_name: string): Location {
  return { kind: "tool", tool_name };
}

export function stepInspectMimic(primary: MimicSite): VerificationStep {
  return {
    step_type: "inspect-description",
    instruction:
      `Open tool "${primary.tool_name}" and read its description. Jump to offset ` +
      `${primary.offset} (length ${primary.length}) and confirm the phrase/shape ` +
      `"${primary.observed}" is present verbatim. Legitimate response-format ` +
      `documentation belongs in the tool's \`outputSchema\`, not in the prose ` +
      `description.`,
    target: loc(primary.tool_name),
    expected_observation:
      `The description contains a ${primary.kind === "jsonrpc_shape" ? "literal JSON-RPC envelope" : "protocol-mimic phrase"}: "${primary.label}".`,
  };
}

export function stepInspectAdditionalSignals(
  primary: MimicSite,
  others: MimicSite[],
): VerificationStep {
  const summary = others
    .slice(0, 5)
    .map((h) => `• ${h.label} at offset ${h.offset}`)
    .join("\n");
  return {
    step_type: "inspect-description",
    instruction:
      `Locate every remaining protocol-mimic signal inside tool ` +
      `"${primary.tool_name}"'s description:\n${summary}` +
      (others.length > 5 ? `\n... and ${others.length - 5} more` : ""),
    target: loc(primary.tool_name),
    expected_observation:
      `${others.length} additional signal(s) present; each represents an ` +
      `independent phrase/shape whose noisy-OR weight contributed to the aggregate.`,
  };
}

export function stepRelocateToSchema(primary: MimicSite): VerificationStep {
  return {
    step_type: "compare-baseline",
    instruction:
      `Move any structural response-shape documentation out of tool ` +
      `"${primary.tool_name}"'s description and into its \`outputSchema\`. ` +
      `The description should describe what the tool DOES, not mimic protocol ` +
      `traffic. Re-run the scanner — a structural-only rewrite should produce ` +
      `zero G3 findings.`,
    target: loc(primary.tool_name),
    expected_observation:
      `A rewrite that removes protocol-mimic prose and literal JSON-RPC shapes ` +
      `from the description produces zero G3 matches on re-scan.`,
  };
}
