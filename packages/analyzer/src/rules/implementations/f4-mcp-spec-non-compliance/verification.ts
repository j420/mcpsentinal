/**
 * F4 verification-step builders — every step carries a structured
 * Location target (v2 standard §4). An auditor reads the steps, opens
 * the tools/list response, and confirms the spec field the rule cited.
 *
 * No regex, no long string-literal arrays.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { F4Site } from "./gather.js";

/** Step — inspect the offending tool entry in tools/list. */
export function stepInspectToolEntry(site: F4Site): VerificationStep {
  return {
    step_type: "inspect-schema",
    instruction:
      `Enumerate the server's tools via tools/list and locate the tool entry that ` +
      `triggered the finding. The scanner classified the spec-field violation as ` +
      `"${site.fieldClass}" (${site.fieldEntry.requirement} by MCP spec ` +
      `${site.fieldEntry.spec_revision}).`,
    target: site.toolLocation,
    expected_observation:
      describeExpectedObservation(site),
  };
}

/** Step — confirm the structural classification against the spec. */
export function stepCompareAgainstSpec(site: F4Site): VerificationStep {
  return {
    step_type: "compare-baseline",
    instruction:
      `Compare the tool entry against MCP specification revision ` +
      `${site.fieldEntry.spec_revision} at ` +
      `modelcontextprotocol.io/specification. The spec describes the ` +
      `${site.fieldEntry.requirement} field class this finding covers. Confirm ` +
      `the entry omits (or empties) the named field and note which spec revision ` +
      `the server declared during initialize.`,
    target: site.toolLocation,
    expected_observation:
      `The spec explicitly classifies the field as ${site.fieldEntry.requirement}; ` +
      `the observed tool omits or empties it.`,
  };
}

function describeExpectedObservation(site: F4Site): string {
  switch (site.fieldClass) {
    case "tool-name-empty":
      return `The tool entry has a null, undefined, or empty-string \`name\` field.`;
    case "tool-name-whitespace":
      return `The tool entry's \`name\` field is present but contains only whitespace.`;
    case "tool-description-missing":
      return `The tool entry has a null, undefined, or empty-after-trim \`description\` field.`;
    case "tool-input-schema-missing":
      return `The tool entry has no \`inputSchema\` field (null or undefined). An empty object schema is acceptable; total absence is not.`;
  }
}
