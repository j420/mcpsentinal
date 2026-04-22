/**
 * Q15 verification-step builders.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { Q15Site } from "./gather.js";

export function stepInspectA2aSurface(site: Q15Site): VerificationStep {
  const primary = site.a2aSurfaces[0];
  const target: Location = primary.location;
  const kinds = Array.from(new Set(site.a2aSurfaces.map((s) => s.kind))).join(", ");
  return {
    step_type: "inspect-source",
    instruction:
      `Open the reported location and confirm the code reads from an A2A ` +
      `protocol surface (${kinds}). A2A skill descriptions, Part content, ` +
      `push-notification payloads, and agent-discovery results have no ` +
      `native MCP content policy — they cross the boundary raw.`,
    target,
    expected_observation:
      `Observed A2A tokens: ${site.a2aSurfaces.slice(0, 5).map((s) => s.token).join(", ")} ` +
      `(${site.a2aSurfaces.length} total). Each is an input channel the ` +
      `MCP content-policy layer does not see.`,
  };
}

export function stepInspectMcpSink(site: Q15Site): VerificationStep {
  const primary = site.mcpSinks[0];
  return {
    step_type: "inspect-source",
    instruction:
      `Confirm the A2A-sourced value flows into an MCP tool sink ` +
      `("${primary.sinkName}"). Any prompt injection, TextPart / FilePart / ` +
      `DataPart payload, or skill description crossing this sink reaches ` +
      `the client LLM via the MCP tool surface.`,
    target: primary.location,
    expected_observation:
      `MCP sink "${primary.sinkName}" receives a value derived from the ` +
      `A2A surfaces above. The boundary is crossed — the original A2A ` +
      `trust level does not accompany the data.`,
  };
}

export function stepCheckContentPolicy(site: Q15Site): VerificationStep {
  const target: Location =
    site.enclosingFunctionLocation ?? site.mcpSinks[0].location;
  return {
    step_type: "check-config",
    instruction:
      `Walk the enclosing function and verify whether an MCP content policy ` +
      `is applied BEFORE data enters the MCP sink. Look for sanitize / ` +
      `enforceContentPolicy / validateA2APart / scrubA2A / contentPolicy ` +
      `identifiers. Without one, A2A payloads reach MCP consumers raw.`,
    target,
    expected_observation:
      site.contentPolicyIdentifier
        ? `Policy identifier "${site.contentPolicyIdentifier}" observed in ` +
          `scope — the finding is demoted. Confirm the policy runs on the ` +
          `A2A-sourced value along every path.`
        : `No content-policy identifier in scope. A2A-sourced payloads ` +
          `enter the MCP sink unsanitised.`,
  };
}
