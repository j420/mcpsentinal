/**
 * I13 verification-step builders — cross-server audit runbook.
 *
 * Every step carries a `target: Location` per Rule Standard v2. The
 * auditor walks the step list to reproduce the cross-server
 * observation: open Server A's tools, inspect its capability; open
 * Server B; open Server C; verify the AI client has no isolation
 * between them.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { CrossServerLeg, ServerContribution } from "./gather.js";

/**
 * Step 1 — visit each leg's contributing tool and confirm the capability.
 */
export function stepInspectLeg(
  legLabel: "private-data" | "untrusted-content" | "external-comms",
  contribution: CrossServerLeg,
): VerificationStep {
  return {
    step_type: "inspect-schema",
    instruction:
      `Open tool "${contribution.tool_name}" on server "${contribution.server_name}" ` +
      `and inspect its input_schema and description. Confirm the capability classification: ` +
      `${legLabel} — ${contribution.attribution}`,
    target: contribution.location,
    expected_observation:
      `A tool whose parameters and description match the ${legLabel} leg of the lethal ` +
      `trifecta at confidence ${(contribution.confidence * 100).toFixed(0)}%.`,
  };
}

/**
 * Step 2 — cross-server data-flow trace. Describes how the AI client
 * bridges Server A → Server B without isolation.
 */
export function stepTraceCrossServerFlow(
  contributions: ServerContribution[],
): VerificationStep {
  const lead = contributions[0];
  return {
    step_type: "trace-flow",
    instruction:
      `Construct a concrete exfiltration scenario: identify a tool from the private-data ` +
      `server that returns sensitive content, a tool from the untrusted-content server ` +
      `that ingests attacker-controlled data, and a tool from the external-comms server ` +
      `that sends arbitrary data out. Verify that the AI client is allowed to call all ` +
      `three tools in the same session without any cross-server approval gate.`,
    target: { kind: "tool", tool_name: lead.tool_names[0] ?? "<unknown>" },
    expected_observation:
      `A read → inject → exfiltrate chain is possible across servers ` +
      `[${contributions.map((c) => c.server_name).join(", ")}] with the AI client as ` +
      `the sole bridge and no trust boundary between them.`,
  };
}

/**
 * Step 3 — check client configuration for cross-server isolation policy.
 */
export function stepCheckClientIsolation(
  contributions: ServerContribution[],
): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Open the MCP client configuration file (claude_desktop_config.json, .cursor/mcp.json, ` +
      `or similar) and confirm that all the listed servers are configured for the SAME user ` +
      `session with no per-server isolation, no per-session approval, and no destination ` +
      `allowlist on the external-comms server.`,
    target: {
      kind: "config",
      file: "mcp-client-config.json",
      json_pointer: "/mcpServers",
    },
    expected_observation:
      `All ${contributions.length} servers are configured together in the same client ` +
      `session with no cross-server trust boundary — the AI client treats the entire ` +
      `tool set as a unified capability surface.`,
  };
}
