/**
 * I13 capability-leg registry.
 *
 * Mirrors F1's three-leg vocabulary at a different granularity:
 * F1 classifies tools inside one server; I13 classifies tools
 * across an entire client configuration. The three legs are
 * identical by definition (private-data, untrusted-content,
 * external-comms), so we reuse F1's capability classifications
 * directly from the shared capability-graph analyzer.
 *
 * This file names the three legs at the I13 boundary and holds
 * the per-leg attribution strings that surface in evidence
 * chain rationales. No bare string-literal arrays; the
 * capabilities are declared as typed Records keyed by the
 * capability identifier.
 */

import type { Capability } from "../../../analyzers/capability-graph.js";

export interface LegEntry {
  /** Which trifecta leg this capability fills. */
  leg: "private_data" | "untrusted_content" | "external_comms";
  /** Short attribution shown in ConfidenceFactor rationales. */
  attribution: string;
}

/**
 * Minimum per-capability confidence for a tool to contribute to
 * its leg. Tuned so low-signal matches (confidence < 0.5) don't
 * inflate the trifecta into a false positive.
 */
export const LEG_MIN_CONFIDENCE = 0.5;

/**
 * I13 confidence cap — see CHARTER "Why confidence is capped at 0.90".
 */
export const I13_CONFIDENCE_CAP = 0.9;

/**
 * Private-data leg capabilities.
 */
export const PRIVATE_DATA_CAPS: Partial<Record<Capability, LegEntry>> = {
  "reads-private-data": {
    leg: "private_data",
    attribution: "reads structured private user/org data — source leg of cross-server exfiltration.",
  },
  "manages-credentials": {
    leg: "private_data",
    attribution: "credential-handling capability — private-data exposure.",
  },
  "accesses-filesystem": {
    leg: "private_data",
    attribution: "filesystem access — local private data (config, secrets, home directory).",
  },
};

/**
 * Untrusted-content leg capabilities.
 */
export const UNTRUSTED_CONTENT_CAPS: Partial<Record<Capability, LegEntry>> = {
  "ingests-untrusted": {
    leg: "untrusted_content",
    attribution: "ingests external/untrusted content — injection surface for prompt poisoning.",
  },
  "reads-public-data": {
    leg: "untrusted_content",
    attribution: "fetches public/remote data — attacker-influenceable content source.",
  },
  "receives-network": {
    leg: "untrusted_content",
    attribution: "receives network input — attacker-influenceable content source.",
  },
};

/**
 * External-comms leg capabilities.
 */
export const EXTERNAL_COMMS_CAPS: Partial<Record<Capability, LegEntry>> = {
  "sends-network": {
    leg: "external_comms",
    attribution: "sends outbound network traffic — exfiltration sink leg.",
  },
};
