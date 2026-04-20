/**
 * K4 verification-step builders — every step carries a structured
 * `Location` target (Rule Standard v2 §4). Steps are what an auditor uses
 * to reproduce the observation independently of the scan engine.
 *
 * Zero regex. No string-literal arrays > 5.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type {
  DestructiveCallSite,
  DestructiveTool,
  ConfirmationParam,
} from "./gather.js";

/**
 * Step 1 (schema surface) — confirm the tool's name tokenises to a
 * destructive verb. The auditor opens the tool in the registry and
 * checks the classified tokens.
 */
export function stepInspectToolName(tool: DestructiveTool): VerificationStep {
  return {
    step_type: "inspect-description",
    instruction:
      `Open the tool metadata and confirm that the name "${tool.toolName}" ` +
      `contains the destructive verb "${tool.classification.destructive!.verb}" ` +
      `(tokenised as: ${tool.classification.tokens.join(" / ")}). This is the ` +
      `first piece of evidence the rule requires.`,
    target: tool.toolLocation,
    expected_observation:
      `Tool name tokenises to include the ${tool.classification.destructive!.klass} ` +
      `verb "${tool.classification.destructive!.verb}"${tool.classification.bulk ? " with a bulk marker" : ""}.`,
  };
}

/**
 * Step 2 (schema surface) — confirm the input_schema has no REQUIRED
 * confirmation parameter. Presence of an optional confirm param is
 * insufficient because the AI can omit it.
 */
export function stepInspectSchemaForConfirmation(tool: DestructiveTool): VerificationStep {
  const hasOptional = tool.confirmationParams.some((p) => !p.required);
  return {
    step_type: "inspect-schema",
    instruction:
      hasOptional
        ? `Confirm that the input_schema lists at least one confirmation-like ` +
          `parameter (${tool.confirmationParams.map((p) => p.name).join(", ")}) ` +
          `but NONE is present in the schema's "required" array — the AI client ` +
          `can legally invoke this tool without supplying any of them.`
        : `Confirm that the input_schema exposes no parameter whose name matches ` +
          `confirmation vocabulary (confirm / confirmation / approve / approved / ` +
          `acknowledge / consent / dry_run / preview / force). The AI client has ` +
          `no way to signal human intent.`,
    target: tool.schemaLocation,
    expected_observation:
      hasOptional
        ? `Schema properties include confirmation names, but schema.required does ` +
          `not list any of them.`
        : `Schema properties contain no confirmation parameter.`,
  };
}

/**
 * Step 3 (schema surface) — check the MCP tool annotations for a
 * destructiveHint. When absent, MCP-aware clients cannot be expected to
 * prompt for confirmation — the absence is itself evidence.
 */
export function stepInspectAnnotations(tool: DestructiveTool): VerificationStep {
  return {
    step_type: "inspect-description",
    instruction:
      tool.hasDestructiveHintAnnotation
        ? `Confirm that \`annotations.destructiveHint: true\` is present on the ` +
          `tool. This is a PARTIAL mitigation — MCP-aware clients will prompt; ` +
          `MCP-unaware clients will not.`
        : `Confirm that \`annotations.destructiveHint\` is NOT set on the tool. ` +
          `Without the annotation, even MCP-aware clients cannot know that ` +
          `confirmation is required.`,
    target: tool.toolLocation,
    expected_observation:
      tool.hasDestructiveHintAnnotation
        ? `annotations.destructiveHint === true; still no schema-level gate.`
        : `annotations.destructiveHint is absent or false.`,
  };
}

/**
 * Step 4 (code surface) — open the destructive call site and confirm
 * the call symbol, bulk class, and the absence of a confirmation guard
 * in the ancestor chain.
 */
export function stepInspectDestructiveCall(site: DestructiveCallSite): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the file at this line. Confirm the call symbol ` +
      `"${site.callSymbol.raw}" is a destructive operation ` +
      `(verb: "${site.callSymbol.destructive!.verb}", ` +
      `class: ${site.callSymbol.destructive!.klass}` +
      `${site.callSymbol.bulk ? ", bulk=true" : ""}), and that the enclosing ` +
      `function body contains no confirmation call (confirm/prompt/approve/ask/` +
      `verify/acknowledge/requireConfirmation/requestApproval/elicit) and no ` +
      `IfStatement whose condition references a force/confirm/approved flag.`,
    target: site.location,
    expected_observation:
      `A destructive call with no confirmation guard in any enclosing scope.`,
  };
}

/**
 * Step 5 (code surface, mitigated) — when a guard WAS found, the rule
 * does not emit a finding. This builder is used for the negative path of
 * the chain-integrity test suite.
 */
export function stepInspectMitigatedCall(site: DestructiveCallSite): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Confirm the guard at this location dominates the destructive call ` +
      `on line ${site.location.kind === "source" ? site.location.line : "?"}: ` +
      `guarded-by condition(${site.guard.conditionIdentifiers.join(", ") || "—"}), ` +
      `guard-calls(${site.guard.guardCalls.join(", ") || "—"}), ` +
      `receiver-methods(${site.guard.guardReceiverMethods.join(", ") || "—"}).`,
    target: site.guard.guardLocation ?? site.location,
    expected_observation:
      `A confirmation guard is on the control-flow path to the destructive call.`,
  };
}

/**
 * Step 6 — confirm the confirmation-parameter check for schema findings.
 */
export function stepInspectConfirmationParam(
  tool: DestructiveTool,
  param: ConfirmationParam,
): VerificationStep {
  const target: Location = {
    kind: "schema",
    tool_name: tool.toolName,
    json_pointer: param.jsonPointer,
  };
  return {
    step_type: "inspect-schema",
    instruction:
      param.required
        ? `Confirm the confirmation parameter "${param.name}" is listed in ` +
          `\`required\` and its kind (${param.kind}) blocks bare invocation.`
        : `Confirm the confirmation parameter "${param.name}" exists but is NOT ` +
          `listed in \`required\` — the AI can omit it entirely.`,
    target,
    expected_observation:
      param.required
        ? `Parameter "${param.name}" is required — the rule should NOT fire.`
        : `Parameter "${param.name}" is optional — an attacker-controlled client ` +
          `can skip it.`,
  };
}
