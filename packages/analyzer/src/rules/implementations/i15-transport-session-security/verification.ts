import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { I15Hit } from "./gather.js";

export function stepInspectSource(hit: I15Hit): VerificationStep {
  const target: Location = {
    kind: "source",
    file: "<server source>",
    line: hit.line_number,
  };
  return {
    step_type: "inspect-source",
    instruction:
      `Open the server source at line ${hit.line_number}. Verify whether the ` +
      `${hit.spec.kind} anti-pattern (${hit.spec.description}) is the ` +
      `production path. Use crypto.randomUUID() / secureRandom() for tokens; ` +
      `set secure: true, httpOnly: true, sameSite: 'strict' on cookies.`,
    target,
    expected_observation: hit.line_preview,
  };
}

export function stepCompareCve(): VerificationStep {
  const target: Location = {
    kind: "source",
    file: "<server source>",
    line: 1,
  };
  return {
    step_type: "compare-baseline",
    instruction:
      "Cross-reference CVE-2025-6515. The MCP Streamable HTTP transport is " +
      "currently in-the-wild exploited against predictable session tokens. " +
      "Ensure the observed pattern is not present on the production path.",
    target,
    expected_observation:
      "The source file matches one of the CVE-2025-6515-class anti-patterns.",
  };
}
