/**
 * G1 verification-step factories.
 *
 * Each step carries a structured `Location` target (Rule Standard v2 §4)
 * so an auditor can open the exact tool / capability / resource the
 * chain references. No prose-string targets, no regex.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { GatewayNode, SinkNode } from "./gather.js";

/**
 * Step — verify the ingestion gateway. Auditor opens the tool (or
 * resource) declaration and confirms the classifier's decision.
 */
export function buildIngestionSourceStep(gateway: GatewayNode): VerificationStep {
  const target: Location =
    gateway.origin === "resource"
      ? {
          kind: "resource",
          uri: gateway.resource_uri ?? gateway.tool_name,
          field: "uri",
        }
      : { kind: "tool", tool_name: gateway.tool_name };
  const label =
    gateway.origin === "resource"
      ? `MCP resource "${gateway.tool_name}"`
      : `tool "${gateway.tool_name}"`;
  return {
    step_type: "inspect-description",
    instruction:
      `Open ${label} and confirm it ingests attacker-reachable content ` +
      `(ingestion-kind: ${gateway.ingestion_kind}, trust-boundary: ` +
      `${gateway.trust_boundary}). The capability classifier attributed the ` +
      `gateway as: "${gateway.attribution}".`,
    target,
    expected_observation:
      `${label} returns content an external party can influence — web ` +
      `page, email body, issue comment, shared file, chat message, or ` +
      `MCP resource payload — at or above confidence ` +
      `${(gateway.confidence * 100).toFixed(0)}%.`,
  };
}

/**
 * Step — trace the propagation. The MCP tools surface IS the channel:
 * the gateway's response flows into the agent's context, and the agent's
 * subsequent tool call carries the (possibly injected) instruction into
 * the sink.
 */
export function buildAgentContextPropagationStep(
  gateway: GatewayNode,
  primary_sink: SinkNode,
): VerificationStep {
  const target: Location = { kind: "capability", capability: "tools" };
  return {
    step_type: "trace-flow",
    instruction:
      `Walk the propagation: response of "${gateway.tool_name}" enters the ` +
      `agent's reasoning context; any prompt-injection content within that ` +
      `response can direct the agent to invoke "${primary_sink.tool_name}". ` +
      `Confirm the server does not interpose an isolation boundary between ` +
      `the gateway's response and the sink's invocation (no sanitiser, no ` +
      `per-sink confirmation gate, no data-flow labels).`,
    target,
    expected_observation:
      `Agent receives "${gateway.tool_name}" output verbatim, treats it as ` +
      `reasoning input, and can invoke "${primary_sink.tool_name}" on the ` +
      `same session without crossing a trust boundary.`,
  };
}

/** Step — verify the sink leg. Auditor opens the sink and confirms side effect. */
export function buildSinkStep(sink: SinkNode): VerificationStep {
  const target: Location = { kind: "tool", tool_name: sink.tool_name };
  return {
    step_type: "inspect-schema",
    instruction:
      `Open the tool "${sink.tool_name}" and confirm its side effect matches ` +
      `the sink role "${sink.sink_role}". For network_egress, check for ` +
      `URL / webhook / recipient params. For filesystem_write, check for ` +
      `path / content params. The classifier attributed this sink as: ` +
      `"${sink.attribution}".`,
    target,
    expected_observation:
      `Tool "${sink.tool_name}" produces the side effect the classifier ` +
      `tagged (${sink.sink_role}) at or above confidence ` +
      `${(sink.confidence * 100).toFixed(0)}%.`,
  };
}

/**
 * Step — verify the mitigation. Produced only when the gather step
 * detected a sanitizer parameter on the gateway. The auditor opens the
 * parameter and confirms the sanitizer is actually enforced (the
 * parameter could be declared but default-false — in which case the
 * mitigation is cosmetic).
 */
export function buildMitigationStep(
  gateway: GatewayNode,
  parameter: string,
): VerificationStep {
  const target: Location = {
    kind: "parameter",
    tool_name: gateway.tool_name,
    parameter_path: `input_schema.properties.${parameter}`,
  };
  return {
    step_type: "inspect-schema",
    instruction:
      `Open the "${parameter}" parameter of "${gateway.tool_name}" and ` +
      `confirm it defaults to enabled and is actually enforced on every ` +
      `call. A declared-but-default-off sanitizer is not a mitigation — ` +
      `the agent can be instructed to disable it.`,
    target,
    expected_observation:
      `Parameter "${parameter}" defaults to a value that enforces sanitisation ` +
      `on every tool call, and the server rejects calls that attempt to disable ` +
      `it.`,
  };
}
