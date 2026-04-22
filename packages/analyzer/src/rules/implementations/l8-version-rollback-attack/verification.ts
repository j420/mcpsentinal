import type { VerificationStep } from "../../../evidence.js";
import type { RollbackSite } from "./gather.js";

export function stepInspectOverride(site: RollbackSite): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      site.kind === "json-override"
        ? `Open package.json and navigate to ${site.section_or_line}.${site.package_name}. ` +
          `Confirm the pinned version "${site.version_spec}" is the intended policy.`
        : `Open the file at ${site.section_or_line}. Confirm the install command ` +
          `pins "${site.package_name}" to "${site.version_spec}" and that this is intended.`,
    target: site.location,
    expected_observation:
      `Package "${site.package_name}" pinned to "${site.version_spec}".`,
  };
}

export function stepCheckCve(site: RollbackSite): VerificationStep {
  return {
    step_type: "check-dependency",
    instruction:
      `Consult OSV / GHSA for ${site.package_name}@${site.version_spec}. ` +
      `Confirm whether this version has any published advisory. A rollback ` +
      `is only exploitable if the pinned version carries a known CVE.`,
    target: site.location,
    expected_observation:
      `CVEs present in ${site.package_name}@${site.version_spec}.`,
  };
}

export function stepCheckCritical(site: RollbackSite): VerificationStep {
  return {
    step_type: "check-config",
    instruction: site.is_mcp_critical
      ? `Package "${site.package_name}" matches an MCP-critical prefix ` +
        `(mcp / modelcontextprotocol / fastmcp / anthropic / openai). ` +
        `Confirm the rollback was reviewed by a maintainer with knowledge of ` +
        `the SDK's version-specific security fixes.`
      : `Package "${site.package_name}" is not in the MCP-critical prefix ` +
        `list. The rollback severity is HIGH rather than CRITICAL.`,
    target: site.location,
    expected_observation: site.is_mcp_critical
      ? `Reviewer approval documented.`
      : `Package is general-purpose.`,
  };
}
