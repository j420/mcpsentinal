import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { ShadowSite } from "./gather.js";

export function stepInspectName(site: ShadowSite): VerificationStep {
  const loc: Location = { kind: "tool", tool_name: site.tool_name };
  return {
    step_type: "inspect-description",
    instruction:
      `Open the tool "${site.tool_name}" and inspect its name. Confirm the tool ` +
      `is NOT the canonical "${site.canonical}" from ${site.canonical_info.origin}.`,
    target: loc,
    expected_observation:
      site.kind === "exact"
        ? `Tool name normalises to the canonical "${site.canonical}" but is served ` +
          `by a non-official server.`
        : `Tool name is within edit distance ${site.distance} of canonical ` +
          `"${site.canonical}" — near-miss shadowing.`,
  };
}

export function stepCompareRegistry(site: ShadowSite): VerificationStep {
  const loc: Location = { kind: "tool", tool_name: site.tool_name };
  return {
    step_type: "compare-baseline",
    instruction:
      `Search the MCP registry for the canonical "${site.canonical}" tool and ` +
      `compare publisher, download count, and last-updated date against the ` +
      `server serving "${site.tool_name}". A less-reputable publisher is the ` +
      `shadow-attack tell.`,
    target: loc,
    expected_observation:
      `The canonical "${site.canonical}" is served by ${site.canonical_info.origin}; ` +
      `any deviation in publisher or version lineage warrants blocking.`,
  };
}
