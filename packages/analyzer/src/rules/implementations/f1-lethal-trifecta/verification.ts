/**
 * F1 verification-step factories.
 *
 * Each step carries a structured Location target (Rule Standard v2 §4) so
 * an auditor can open the exact tool/schema/capability position the chain
 * references. No prose-string targets, no regex.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { LegContribution, CompanionPattern } from "./gather.js";

/**
 * Step — verify the private-data leg of the trifecta. The auditor opens
 * each contributing tool's schema and confirms the classification.
 */
export function stepVerifyPrivateDataLeg(
  contributions: LegContribution[],
): VerificationStep {
  const primary = contributions[0];
  const target: Location = { kind: "tool", tool_name: primary.tool_name };
  const others =
    contributions.length > 1
      ? ` (plus ${contributions.length - 1} more node${contributions.length > 2 ? "s" : ""})`
      : "";
  return {
    step_type: "inspect-schema",
    instruction:
      `Open the tool definition for "${primary.tool_name}"${others} and confirm it reads private ` +
      `data — check parameter semantics (credential / file-path / identifier), the response ` +
      `shape (object-returning with user-record structure), and the tool description's data ` +
      `access wording. The capability classifier attributed this leg as: "${primary.attribution}".`,
    target,
    expected_observation:
      `At least one tool/resource node in {${contributions.map((c) => c.tool_name).join(", ")}} ` +
      `exposes parameters or a response shape consistent with reading private data at or above ` +
      `confidence ${(primary.confidence * 100).toFixed(0)}%.`,
  };
}

/**
 * Step — verify the untrusted-content leg. The auditor confirms the tool
 * ingests attacker-reachable content (web, email, issue tracker, shared
 * file system).
 */
export function stepVerifyUntrustedLeg(
  contributions: LegContribution[],
): VerificationStep {
  const primary = contributions[0];
  const target: Location = { kind: "tool", tool_name: primary.tool_name };
  return {
    step_type: "inspect-description",
    instruction:
      `Read the tool description for "${primary.tool_name}" and confirm its input source is ` +
      `outside the user's trust boundary — web scrape, email body, issue-tracker comment, ` +
      `uploaded file, or chat feed. The capability classifier attributed this leg as: ` +
      `"${primary.attribution}".`,
    target,
    expected_observation:
      `At least one tool in {${contributions.map((c) => c.tool_name).join(", ")}} consumes ` +
      `content that an external party can influence — this is the injection vehicle for the ` +
      `trifecta.`,
  };
}

/**
 * Step — verify the external-comms leg. The auditor confirms the tool
 * performs genuine external egress (not internal service bus, not
 * localhost-only).
 */
export function stepVerifyExternalCommsLeg(
  contributions: LegContribution[],
): VerificationStep {
  const primary = contributions[0];
  const target: Location = { kind: "tool", tool_name: primary.tool_name };
  return {
    step_type: "inspect-schema",
    instruction:
      `Open the tool definition for "${primary.tool_name}" and confirm its network target is ` +
      `external — inspect URL / webhook / recipient parameters for host patterns beyond ` +
      `localhost. The capability classifier attributed this leg as: "${primary.attribution}".`,
    target,
    expected_observation:
      `At least one tool in {${contributions.map((c) => c.tool_name).join(", ")}} can send data ` +
      `to an external endpoint — this is the exfiltration sink.`,
  };
}

/**
 * Step — trace cross-tool reachability. Without isolation, a poisoned read
 * in the untrusted-content leg can instruct the AI to pipe private-data
 * output through the network-send leg.
 */
export function stepTraceCrossToolFlow(
  privateNode: string,
  networkNode: string,
): VerificationStep {
  const target: Location = { kind: "tool", tool_name: networkNode };
  return {
    step_type: "trace-flow",
    instruction:
      `Starting from "${privateNode}" (private-data leg), walk the capability graph toward ` +
      `"${networkNode}" (external-comms leg). Confirm the server does not enforce a data-flow ` +
      `boundary between them — no destination allowlist, no per-tool data classification, no ` +
      `human-in-the-loop gate on the network tool.`,
    target,
    expected_observation:
      `Data read by "${privateNode}" can flow, via the AI agent's own tool orchestration, into ` +
      `"${networkNode}"'s request body without traversing an isolation boundary.`,
  };
}

/** Step — verify a companion-pattern finding (F2 / F3 / F6). */
export function stepVerifyCompanion(companion: CompanionPattern): VerificationStep {
  const tools = toolsOfCompanion(companion);
  const primary = tools[0] ?? "<unknown>";
  const target: Location = { kind: "tool", tool_name: primary };
  const description = descriptionOfCompanion(companion);
  return {
    step_type: "inspect-schema",
    instruction:
      `Companion pattern (${companion.companion}) detected during the same graph pass. ` +
      `Confirm the pattern on the named tools: ${description}`,
    target,
    expected_observation:
      `Tools {${tools.join(", ")}} exhibit the ${companion.companion} precondition the ` +
      `capability / schema analyzer reported.`,
  };
}

function toolsOfCompanion(companion: CompanionPattern): string[] {
  if (companion.origin === "graph") {
    return companion.pattern.type === "unrestricted_access"
      ? []
      : (companion.pattern as { tools_involved: string[] }).tools_involved;
  }
  return (companion.pattern as { tools: string[] }).tools;
}

function descriptionOfCompanion(companion: CompanionPattern): string {
  if (companion.origin === "graph") {
    return (companion.pattern as { description: string }).description;
  }
  return (companion.pattern as { evidence: string }).evidence;
}
