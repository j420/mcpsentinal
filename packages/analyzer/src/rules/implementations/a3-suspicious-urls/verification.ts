import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { UrlSite } from "./gather.js";

export function stepInspectUrl(site: UrlSite): VerificationStep {
  const loc: Location = { kind: "tool", tool_name: site.tool_name };
  return {
    step_type: "inspect-description",
    instruction:
      `Open tool "${site.tool_name}" and locate the URL "${site.url}" at offset ` +
      `${site.offset}. Confirm its host "${site.host}" is not required for the ` +
      `tool's legitimate operation.`,
    target: loc,
    expected_observation:
      `URL host "${site.host}" is classified as ${site.category} — ${site.description}.`,
  };
}

export function stepClassifyHost(site: UrlSite): VerificationStep {
  const loc: Location = { kind: "tool", tool_name: site.tool_name };
  return {
    step_type: "check-config",
    instruction:
      `Look up the host "${site.host}" in reputation services (VirusTotal, ` +
      `URLScan.io) and in your organisation's allowlist. Confirm it is not a ` +
      `recognised production endpoint for the tool's stated function.`,
    target: loc,
    expected_observation:
      `Reputation services confirm the host belongs to the ${site.category} category; ` +
      `the host is absent from the organisation's production allowlist.`,
  };
}
