/**
 * G6 verification-step builders. An auditor reads the steps and
 * reconstructs the diff against the baseline fingerprint record.
 *
 * No regex, no long string-literal arrays.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { AddedTool, ModifiedTool } from "./gather.js";
import type { Location } from "../../location.js";

export function stepInspectAddedTool(tool: AddedTool): VerificationStep {
  return {
    step_type: "inspect-schema",
    instruction:
      `Call tools/list on the server and confirm a tool named "${tool.name}" ` +
      `is present today but was absent from the previous scan's pin record ` +
      `(hash ${tool.hash.slice(0, 12)}…). If the tool is present in today's ` +
      `response, the rule's added-tool claim is verified.`,
    target: tool.toolLocation,
    expected_observation:
      tool.danger === null
        ? `Tool "${tool.name}" is present in today's tools/list response but ` +
          `was absent from the baseline.`
        : `Tool "${tool.name}" is present in today's tools/list response but ` +
          `was absent from the baseline. Its name matches the ` +
          `${tool.danger.class} vocabulary.`,
  };
}

export function stepCompareBaseline(capabilityLocation: Location): VerificationStep {
  return {
    step_type: "compare-baseline",
    instruction:
      `Compare today's tools/list canonical fingerprint (computed by ` +
      `pinServerTools in packages/analyzer/src/tool-fingerprint.ts) against ` +
      `the previous scan's pin stored in the scan history. Confirm the diff ` +
      `recorded here matches the one the scanner computed.`,
    target: capabilityLocation,
    expected_observation:
      `The current pin's composite_hash differs from the baseline's ` +
      `composite_hash, and the added/modified lists match what the finding ` +
      `reports.`,
  };
}

export function stepInspectModifiedTool(tool: ModifiedTool): VerificationStep {
  return {
    step_type: "compare-baseline",
    instruction:
      `Open the current tool entry for "${tool.name}" and compare its ` +
      `${tool.changedFields.join(", ")} field(s) against the baseline. The ` +
      `same-named tool's content has been mutated — this is the "keeps its ` +
      `name, changes its instructions" rug-pull variant.`,
    target: tool.toolLocation,
    expected_observation:
      `Tool "${tool.name}" field(s) [${tool.changedFields.join(", ")}] differ ` +
      `from the baseline. Previous hash ${tool.previousHash.slice(0, 12)}…, ` +
      `current hash ${tool.currentHash.slice(0, 12)}….`,
  };
}
