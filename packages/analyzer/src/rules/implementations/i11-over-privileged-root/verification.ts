import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { I11Fact } from "./gather.js";

export function stepInspectRootDeclaration(fact: I11Fact): VerificationStep {
  const target: Location = {
    kind: "resource",
    uri: fact.root_uri,
    field: "uri",
  };
  return {
    step_type: "check-config",
    instruction:
      `Open the server's roots declaration and verify whether root "${fact.root_uri}" ` +
      `is required for the server's declared purpose. The root covers ` +
      `${fact.match.kind} territory (${fact.match.rationale}). Ask whether ` +
      `the root can be narrowed to a specific project subdirectory that ` +
      `contains only the files the server genuinely needs.`,
    target,
    expected_observation:
      `The root could be narrowed without functional loss; the declaration ` +
      `exposes ${fact.match.kind} paths unnecessarily.`,
  };
}

export function stepCrossReferenceCve(fact: I11Fact): VerificationStep {
  const target: Location = {
    kind: "resource",
    uri: fact.root_uri,
    field: "uri",
  };
  return {
    step_type: "compare-baseline",
    instruction:
      "Cross-reference CVE-2025-53109 / 53110: the Anthropic filesystem MCP " +
      "server's root boundary was bypassed despite a declared root. Overly " +
      "broad roots (file:///, /etc, ~/.ssh, ~/.aws, /proc) amplify the " +
      "consequence of any comparable bypass. Confirm the client enforces " +
      "root containment or narrow the root at the server.",
    target,
    expected_observation:
      "Root is at a sensitive path; client-level containment is not " +
      "guaranteed by the MCP spec.",
  };
}
