/**
 * F7 transform-capability registry.
 *
 * A multi-step exfiltration chain has three classes of node:
 *
 *   1. Reader  — capabilities that source sensitive data.
 *   2. Transformer — encoders, compressors, encrypters that launder bytes
 *      into a URL-safe / log-safe shape.
 *   3. Sender  — capabilities that egress to an external endpoint.
 *
 * This file names class 1 and class 3; the capability-graph analyzer
 * already produces these as tags. Class 2 is documented here for
 * reviewer context — the capability-graph does not currently produce a
 * dedicated "transforms-data" tag, so F7's structural argument treats
 * any intermediate hop on the graph path as a potential transformer.
 *
 * No bare string-arrays — every tag is a typed record entry.
 */

import type { Capability } from "../../../analyzers/capability-graph.js";

/** Capability tag with rationale for why it qualifies as a chain leg. */
export interface ChainLegEntry {
  /** Which part of the chain this capability fills. */
  role: "reader" | "sender";
  /** Short attribution visible in evidence rationale. */
  attribution: string;
  /** Minimum confidence at which the capability contributes. */
  min_confidence: number;
}

/** Reader-class capabilities — data the attacker wants off the machine. */
export const READER_CAPABILITIES: Partial<Record<Capability, ChainLegEntry>> = {
  "reads-private-data": {
    role: "reader",
    attribution:
      "Reads structured private data (user records, credentials, secrets) — " +
      "the starting byte source of the exfiltration chain.",
    min_confidence: 0.5,
  },
  "accesses-filesystem": {
    role: "reader",
    attribution:
      "Filesystem read — covers local documents, SSH keys, config files, " +
      "the workhorse reader on developer-workstation MCP deployments.",
    min_confidence: 0.5,
  },
  "manages-credentials": {
    role: "reader",
    attribution:
      "Credential handling — credentials are exfil-worthy data by themselves " +
      "AND unlock further reads via the services they authenticate.",
    min_confidence: 0.5,
  },
  "reads-public-data": {
    role: "reader",
    attribution:
      "Public-data reader — included because 'public' is a label, not a " +
      "guarantee: once a public reader is the entry hop of a chain, any " +
      "content it returns can carry attacker-controlled payload that the " +
      "downstream sender will egress.",
    min_confidence: 0.5,
  },
};

/** Sender-class capabilities — the egress leg. */
export const SENDER_CAPABILITIES: Partial<Record<Capability, ChainLegEntry>> = {
  "sends-network": {
    role: "sender",
    attribution:
      "Initiates external network egress — HTTP, webhook, email, IM, " +
      "the terminal hop of the exfiltration chain.",
    min_confidence: 0.5,
  },
};

/** Charter confidence cap. */
export const F7_CONFIDENCE_CAP = 0.9;

/**
 * Minimum chain length. A 2-hop chain is the minimum structural case
 * (reader directly feeds sender). Longer chains with transformation hops
 * contribute an additional confidence factor but do not gate firing.
 */
export const F7_MIN_CHAIN_LENGTH = 2;
