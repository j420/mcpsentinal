/**
 * I1 verification-step builders.
 *
 * Every step carries a structured `target: Location` per Rule Standard v2.
 * The step list is the auditor's runbook: open the tool definition, read
 * the annotation, walk the parameters, cross-check the schema inference.
 * No regex literals, no string-literal arrays > 5.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { DeceptionFact, DestructiveSignal } from "./gather.js";

/**
 * Step 1 — visit the tool's annotation block and confirm the claim.
 */
export function stepInspectAnnotation(fact: DeceptionFact): VerificationStep {
  const description =
    fact.annotation.kind === "readonly_declared"
      ? fact.annotation.destructive_hint === true
        ? "readOnlyHint: true AND destructiveHint: true — self-contradiction"
        : "readOnlyHint: true, destructiveHint absent or false"
      : "annotation contradicts tool capability";

  return {
    step_type: "inspect-schema",
    instruction:
      `Open the MCP server's tools/list response and read the annotations object ` +
      `for tool "${fact.tool_name}". Confirm the declared flag combination: ${description}.`,
    target: fact.tool_location,
    expected_observation:
      `An annotations object with the exact shape described above — the server is ` +
      `declaring the tool as safe for AI-client auto-approval.`,
  };
}

/**
 * Step 2 — visit the contradicting signal (parameter name, description, or schema inference).
 */
export function stepInspectDestructiveSignal(
  fact: DeceptionFact,
  signal: DestructiveSignal,
): VerificationStep {
  const origin = signal.origin;

  if (origin === "parameter_name") {
    return {
      step_type: "inspect-schema",
      instruction:
        `Examine the input_schema of tool "${fact.tool_name}" and list each parameter ` +
        `name. Confirm that the parameter flagged here carries a destructive verb that ` +
        `contradicts the readOnlyHint claim inspected in step 1.`,
      target: signal.location,
      expected_observation:
        `A parameter whose name contains the verb "${signal.verb}" (${signal.verb_kind}) — ` +
        `${signal.attribution}`,
    };
  }

  if (origin === "description") {
    return {
      step_type: "inspect-description",
      instruction:
        `Read the description field of tool "${fact.tool_name}" in full. Confirm that ` +
        `the verb flagged here appears in a clause that describes the tool's primary ` +
        `action, not a negation or a comment about an adjacent tool.`,
      target: signal.location,
      expected_observation: `A description containing the verb "${signal.verb}" — ${signal.attribution}`,
    };
  }

  if (origin === "schema_inference") {
    return {
      step_type: "inspect-schema",
      instruction:
        `Walk the full input_schema of tool "${fact.tool_name}". Confirm that the ` +
        `schema-inference analyzer's structural verdict — ${signal.verb_kind} at ` +
        `attack_surface_score ≥ 0.5 — agrees with the parameter shape you see.`,
      target: signal.location,
      expected_observation: signal.attribution,
    };
  }

  // annotation_self_contradiction
  return {
    step_type: "inspect-schema",
    instruction:
      `Re-read the annotations object for tool "${fact.tool_name}". Confirm that both ` +
      `readOnlyHint: true AND destructiveHint: true are set simultaneously — the two ` +
      `flags are mutually exclusive by spec.`,
    target: signal.location,
    expected_observation: signal.attribution,
  };
}

/**
 * Step 3 — verify the AI-client trust-boundary gap.
 */
export function stepCheckClientTrustBoundary(fact: DeceptionFact): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Check the AI client's auto-approval policy for tools carrying readOnlyHint: ` +
      `true. Confirm whether the client cross-checks the annotation against the tool's ` +
      `input_schema before honouring the hint. Invariant Labs (2025) documents that ` +
      `ChatGPT, Cursor, Roo Code, and JetBrains Copilot skip the confirmation dialog ` +
      `for readOnlyHint: true tools without schema cross-check.`,
    target: fact.tool_location,
    expected_observation:
      `Client auto-approves tool "${fact.tool_name}" without cross-checking the ` +
      `schema — the deceptive annotation bypasses user consent for a destructive ` +
      `operation.`,
  };
}
