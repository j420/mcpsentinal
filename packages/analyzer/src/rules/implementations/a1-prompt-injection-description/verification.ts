/**
 * A1 verification-step builders — each step's target is a structured
 * Location the auditor can open and inspect.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { PhraseMatchSite } from "./gather.js";

export function stepInspectPrimary(tool_name: string, primary: PhraseMatchSite): VerificationStep {
  const loc: Location = { kind: "tool", tool_name };
  return {
    step_type: "inspect-description",
    instruction:
      `Open tool "${tool_name}" and read its description. Jump to offset ` +
      `${primary.offset} (length ${primary.length}) and confirm the phrase ` +
      `"${primary.observed}" is present verbatim. Look for behavioural-directive ` +
      `language surrounding it.`,
    target: loc,
    expected_observation:
      `The description contains the ${primary.kind} "${primary.label}" at offset ` +
      `${primary.offset} in the tool-description field.`,
  };
}

export function stepInspectSecondary(tool_name: string, hits: PhraseMatchSite[]): VerificationStep {
  const loc: Location = { kind: "tool", tool_name };
  const summary = hits
    .slice(0, 5)
    .map((h) => `• ${h.label} at offset ${h.offset}`)
    .join("\n");
  return {
    step_type: "inspect-description",
    instruction:
      `Locate every remaining injection signal inside tool "${tool_name}"'s ` +
      `description and confirm each is present as reported:\n${summary}` +
      (hits.length > 5 ? `\n... and ${hits.length - 5} more` : ""),
    target: loc,
    expected_observation:
      `${hits.length} additional signal(s) present; each represents an independent ` +
      `phrase/token whose noisy-OR weight contributed to the aggregate confidence.`,
  };
}

export function stepRemoveDirectives(tool_name: string): VerificationStep {
  const loc: Location = { kind: "tool", tool_name };
  return {
    step_type: "compare-baseline",
    instruction:
      `Rewrite the description for tool "${tool_name}" to describe only what the ` +
      `tool does ("This tool fetches X and returns Y.") with no imperative ` +
      `directives, no authority claims, no references to prior approvals, and no ` +
      `LLM control tokens. Re-run the scanner — a benign description should ` +
      `produce zero A1 findings.`,
    target: loc,
    expected_observation:
      `A descriptive-only rewrite produces zero A1 matches when re-scanned.`,
  };
}
