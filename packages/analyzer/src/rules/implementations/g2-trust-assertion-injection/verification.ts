/**
 * G2 verification-step builders — each step's target is a structured
 * Location the auditor can open and inspect (tool or initialize field).
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { AuthoritySite } from "./gather.js";

function locationFor(site: AuthoritySite): Location {
  if (site.surface === "initialize_instructions") {
    return { kind: "initialize", field: "instructions" };
  }
  return { kind: "tool", tool_name: site.tool_name ?? "<unknown>" };
}

export function stepInspectAuthorityClaim(site: AuthoritySite): VerificationStep {
  const loc = locationFor(site);
  const surfaceLabel =
    site.surface === "initialize_instructions"
      ? "server initialize.instructions"
      : `tool "${site.tool_name}" description`;
  return {
    step_type: "inspect-description",
    instruction:
      `Open ${surfaceLabel}. Jump to offset ${site.offset} (length ${site.length}) ` +
      `and confirm the phrase "${site.observed}" is present verbatim. Check whether ` +
      `the claimed authority can be independently verified (provenance record, ` +
      `signed attestation, external registry) — not via the tool's own prose.`,
    target: loc,
    expected_observation:
      `The ${surfaceLabel} contains the ${site.kind} phrase "${site.label}" at ` +
      `offset ${site.offset}${site.fence_triggered ? " (fence tokens also present — weight demoted)" : ""}.`,
  };
}

export function stepInspectCorroboratingClaims(
  primary: AuthoritySite,
  others: AuthoritySite[],
): VerificationStep {
  const loc = locationFor(primary);
  const summary = others
    .slice(0, 5)
    .map((h) => `• ${h.label} at offset ${h.offset}`)
    .join("\n");
  const surfaceLabel =
    primary.surface === "initialize_instructions"
      ? "server initialize.instructions"
      : `tool "${primary.tool_name}" description`;
  return {
    step_type: "inspect-description",
    instruction:
      `Locate every remaining authority/certification claim inside ${surfaceLabel} ` +
      `and confirm each is present as reported:\n${summary}` +
      (others.length > 5 ? `\n... and ${others.length - 5} more` : ""),
    target: loc,
    expected_observation:
      `${others.length} additional authority signal(s) present; each contributes an ` +
      `independent weight to the noisy-OR aggregate.`,
  };
}

export function stepRemoveClaim(site: AuthoritySite): VerificationStep {
  const loc = locationFor(site);
  const surfaceLabel =
    site.surface === "initialize_instructions"
      ? "server initialize.instructions"
      : `tool "${site.tool_name}" description`;
  return {
    step_type: "compare-baseline",
    instruction:
      `Rewrite ${surfaceLabel} to describe only what the tool does, with no ` +
      `authority claims, certification badges, or trust attestations. If the tool ` +
      `genuinely has external certifications, expose them through a separate ` +
      `provenance channel (registry metadata, signed attestation). Re-run the ` +
      `scanner — a claim-free rewrite should produce zero G2 findings.`,
    target: loc,
    expected_observation:
      `A rewrite without authority claims produces zero G2 matches on re-scan.`,
  };
}
