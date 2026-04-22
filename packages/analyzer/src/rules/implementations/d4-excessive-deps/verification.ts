import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { D4Gathered } from "./gather.js";

export function stepCountManifest(gathered: D4Gathered): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Open the project manifest (package.json / pyproject.toml) and count the direct dependency ` +
      `entries. The scanner reported ${gathered.count} dependencies (threshold: 50). Confirm the ` +
      `count matches what the manifest declares; discrepancies may indicate the audit mixed direct ` +
      `and transitive entries.`,
    target: gathered.manifestLocation,
    expected_observation:
      `Direct dependency count matches the scanner (${gathered.count}).`,
  };
}

export function stepAuditUnused(gathered: D4Gathered): VerificationStep {
  return {
    step_type: "compare-baseline",
    instruction:
      `Run an unused-dependency audit (depcheck for npm, pip-extra-reqs or deptry for Python) and ` +
      `identify deps that can be removed. For a dependency count of ${gathered.count}, even a 10% ` +
      `reduction is a measurable reduction in attack surface.`,
    target: gathered.manifestLocation,
    expected_observation:
      `Multiple dependencies are flagged as unused or as overlapping-functionality candidates for ` +
      `consolidation.`,
  };
}

export function stepCheckMonorepoMarkers(gathered: D4Gathered): VerificationStep {
  const workspaceManifest: Location = {
    kind: "config",
    file: "pnpm-workspace.yaml",
    json_pointer: "/packages",
  };
  return {
    step_type: "check-config",
    instruction:
      `Check for monorepo markers at the repository root: pnpm-workspace.yaml, lerna.json, ` +
      `turbo.json, or a "workspaces" array in package.json. If present, the ${gathered.count} ` +
      `count aggregates every workspace's deps and is expected; dismiss the finding with an audit ` +
      `note.`,
    target: workspaceManifest,
    expected_observation:
      `Either no monorepo marker exists (in which case ${gathered.count} is genuinely a single ` +
      `project's dependency count), or a monorepo marker is present and the finding is a ` +
      `known-benign aggregation artifact.`,
  };
}
