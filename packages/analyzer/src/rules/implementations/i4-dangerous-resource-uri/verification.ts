/**
 * I4 verification-step builders. Each step's `target` is a structured
 * `Location` (not prose) per Rule Standard v2.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";

import type { I4Fact } from "./gather.js";

export function stepInspectResourceUri(fact: I4Fact): VerificationStep {
  const target: Location = {
    kind: "resource",
    uri: fact.resource_uri,
    field: "uri",
  };
  return {
    step_type: "inspect-schema",
    instruction:
      `Open the resource declaration for "${fact.resource_name}" and inspect ` +
      `the uri field. Confirm whether the URI scheme is the one the MCP ` +
      `client will actually resolve or whether the declaration contains a ` +
      `dangerous scheme / traversal marker.`,
    target,
    expected_observation:
      fact.scheme_hit
        ? `The URI starts with ${fact.scheme_hit.scheme} — one of the ` +
          `catalogued dangerous schemes (${fact.scheme_hit.risk_class}).`
        : fact.traversal_hit
          ? `The URI contains the traversal marker "${fact.traversal_hit.marker}" ` +
            `(${fact.traversal_hit.kind}).`
          : "A dangerous marker is observed in the URI.",
  };
}

export function stepCheckRootContainment(fact: I4Fact): VerificationStep {
  const target: Location = {
    kind: "resource",
    uri: fact.resource_uri,
    field: "uri",
  };
  return {
    step_type: "check-config",
    instruction:
      `Compare the URI against the server's declared roots. An MCP client ` +
      `must refuse file:// / data: / javascript: URIs unconditionally, and ` +
      `must verify that any normalised path stays inside every declared ` +
      `root. CVE-2025-53109 demonstrated that this boundary check was ` +
      `missing in the Anthropic filesystem MCP server.`,
    target,
    expected_observation:
      "The resource URI resolves outside declared roots or uses a scheme " +
      "the spec does not require the client to support.",
  };
}
