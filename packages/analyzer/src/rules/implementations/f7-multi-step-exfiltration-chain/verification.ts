/**
 * F7 verification-step factories. Each step's target is a structured
 * Location (Rule Standard v2 §4), never prose.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { ChainEndpoint } from "./gather.js";

/** Step — open the reader tool and confirm its data-reading classification. */
export function stepInspectReader(reader: ChainEndpoint): VerificationStep {
  const target: Location = { kind: "tool", tool_name: reader.tool_name };
  return {
    step_type: "inspect-schema",
    instruction:
      `Open the tool "${reader.tool_name}" and confirm it reads exfil-worthy data. ` +
      `Check parameter semantics (credential / file-path / identifier) and response shape. ` +
      `The classifier attributed this reader as: "${reader.attribution}".`,
    target,
    expected_observation:
      `Tool "${reader.tool_name}" returns data that an attacker would consider worth ` +
      `exfiltrating at or above confidence ${(reader.confidence * 100).toFixed(0)}%.`,
  };
}

/** Step — open the sender tool and confirm it performs external egress. */
export function stepInspectSender(sender: ChainEndpoint): VerificationStep {
  const target: Location = { kind: "tool", tool_name: sender.tool_name };
  return {
    step_type: "inspect-schema",
    instruction:
      `Open the tool "${sender.tool_name}" and confirm its network target is external — ` +
      `inspect URL / webhook / recipient parameters for destinations beyond localhost. ` +
      `The classifier attributed this sender as: "${sender.attribution}".`,
    target,
    expected_observation:
      `Tool "${sender.tool_name}" can send data to an attacker-chosen external endpoint ` +
      `at or above confidence ${(sender.confidence * 100).toFixed(0)}%.`,
  };
}

/**
 * Step — inspect any transformation hop between reader and sender. Encoders,
 * compressors, and encrypters launder sensitive bytes into URL-safe /
 * log-safe form; they are a first-class part of the chain.
 */
export function stepInspectTransformHop(
  hop: string,
  position: number,
  total: number,
): VerificationStep {
  const target: Location = { kind: "tool", tool_name: hop };
  return {
    step_type: "inspect-description",
    instruction:
      `Open the intermediate tool "${hop}" (hop ${position} of ${total} in the chain). ` +
      `Confirm whether it encodes, compresses, encrypts, or otherwise reshapes data. ` +
      `Transformation hops are the laundering step that moves sensitive bytes into a ` +
      `URL-safe form the sender can carry.`,
    target,
    expected_observation:
      `Tool "${hop}" modifies the reader's output in a way that makes it easier to ` +
      `carry across an external network channel.`,
  };
}

/** Step — trace the full hop sequence. */
export function stepTraceChain(hops: string[]): VerificationStep {
  const target: Location = {
    kind: "tool",
    tool_name: hops[hops.length - 1],
  };
  return {
    step_type: "trace-flow",
    instruction:
      `Walk the ${hops.length}-hop chain end-to-end: ${hops.join(" → ")}. Confirm the ` +
      `server does not enforce any data-flow boundary between hops — no data classification ` +
      `labels, no destination allowlist, no human-in-the-loop gate on the sender.`,
    target,
    expected_observation:
      `Data read by "${hops[0]}" can traverse each intermediate hop and reach ` +
      `"${hops[hops.length - 1]}" without crossing an isolation boundary.`,
  };
}
