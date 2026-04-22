/**
 * G5 verification-step builders — every step's `target` is a structured
 * Location the auditor can open and inspect.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { PhraseMatchSite } from "./gather.js";

export function stepInspectPrimary(
  tool_name: string,
  primary: PhraseMatchSite,
): VerificationStep {
  const loc: Location = { kind: "tool", tool_name };
  return {
    step_type: "inspect-description",
    instruction:
      `Open tool "${tool_name}" and read its description. Jump to offset ` +
      `${primary.offset} (length ${primary.length}) and confirm the phrase ` +
      `"${primary.observed}" is present verbatim. The permission noun ` +
      `"${primary.nearby_permission_noun ?? "<none>"}" was observed within ` +
      `8 tokens — verify it co-occurs so the adjacency gate was correctly ` +
      `triggered.`,
    target: loc,
    expected_observation:
      `The description contains the phrase "${primary.label}" at offset ` +
      `${primary.offset}, adjacent to a permission-noun reference.`,
  };
}

export function stepInspectSecondary(
  tool_name: string,
  hits: PhraseMatchSite[],
): VerificationStep {
  const loc: Location = { kind: "tool", tool_name };
  const summary = hits
    .slice(0, 5)
    .map((h) => `• ${h.label} at offset ${h.offset}`)
    .join("\n");
  return {
    step_type: "inspect-description",
    instruction:
      `Locate every remaining prior-approval signal inside tool "${tool_name}"'s ` +
      `description and confirm each is present as reported:\n${summary}` +
      (hits.length > 5 ? `\n... and ${hits.length - 5} more` : ""),
    target: loc,
    expected_observation:
      `${hits.length} additional signal(s) present; each is an independent ` +
      `phrase whose noisy-OR weight contributed to the aggregate confidence.`,
  };
}

export function stepRewriteDescription(tool_name: string): VerificationStep {
  const loc: Location = { kind: "tool", tool_name };
  return {
    step_type: "compare-baseline",
    instruction:
      `Rewrite the description for tool "${tool_name}" so it (a) declares ` +
      `its own required permissions independently (e.g. "Requires read ` +
      `access to /data"), (b) does NOT reference permissions granted to ` +
      `another tool, (c) does NOT reference prior session state or earlier ` +
      `approvals, and (d) does NOT rely on "haven't revoked" language. ` +
      `Re-run the scanner — a compliant rewrite should produce zero G5 ` +
      `findings.`,
    target: loc,
    expected_observation:
      `A description that declares its own permissions independently ` +
      `produces zero G5 matches when re-scanned.`,
  };
}
