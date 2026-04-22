/**
 * F1 capability-leg registry.
 *
 * The lethal trifecta is a conjunction of THREE capability classifications
 * produced by the shared capability-graph analyzer. This file names those
 * three legs, declares the leg confidence threshold, and documents the
 * semantic attribution for each capability tag — so a reviewer can audit
 * why a tag was treated as "this leg" rather than another.
 *
 * No bare string-arrays. Each leg is a typed record keyed by the
 * capability identifier exported from `../../analyzers/capability-graph.ts`.
 */

import type { Capability } from "../../../analyzers/capability-graph.js";

/**
 * Per-leg description of what the capability represents, with the rationale
 * for why it counts as that leg of the trifecta. Surfaced in
 * ConfidenceFactor rationales so each finding explains its own reasoning.
 */
export interface LegEntry {
  /** Which trifecta leg this capability fills. */
  leg: "private_data" | "untrusted_content" | "external_comms";
  /** Short attribution visible in evidence chain rationale. */
  attribution: string;
  /** Minimum confidence at which the capability contributes to the leg. */
  min_confidence: number;
}

/**
 * Private-data leg capabilities. Filesystem access is treated as private-data
 * because the MCP attack surface is predominantly local-host sensitive data
 * (config files, .ssh, home directory). Credential-handling is the
 * highest-signal private-data source.
 */
export const PRIVATE_DATA_CAPABILITIES: Partial<Record<Capability, LegEntry>> = {
  "reads-private-data": {
    leg: "private_data",
    attribution:
      "Tool/resource reads structured private data (user records, " +
      "database rows, credentials) — source leg of exfiltration.",
    min_confidence: 0.5,
  },
  "manages-credentials": {
    leg: "private_data",
    attribution:
      "Credential-handling capability — treated as private-data leg " +
      "because exposure of credentials is indistinguishable from " +
      "exfiltration of the data they unlock.",
    min_confidence: 0.5,
  },
  "accesses-filesystem": {
    leg: "private_data",
    attribution:
      "Filesystem access without a declared root scope — in a local " +
      "MCP deployment this reaches $HOME, .ssh, and configuration " +
      "files that are private by default.",
    min_confidence: 0.5,
  },
};

/**
 * Untrusted-content leg capability. A single tag — the classifier's
 * "ingests-untrusted" signal consolidates multiple entry points (web
 * scrapes, email, issue trackers, uploaded files).
 */
export const UNTRUSTED_CONTENT_CAPABILITIES: Partial<Record<Capability, LegEntry>> = {
  "ingests-untrusted": {
    leg: "untrusted_content",
    attribution:
      "Tool ingests content from an attacker-reachable source — " +
      "web scrape, email, issue tracker, uploaded file, chat feed.",
    min_confidence: 0.5,
  },
};

/**
 * External-communication leg capability. The classifier uses
 * "sends-network" for any egress channel — HTTP clients, webhooks,
 * email transports, Slack / Discord / Telegram bots.
 */
export const EXTERNAL_COMMS_CAPABILITIES: Partial<Record<Capability, LegEntry>> = {
  "sends-network": {
    leg: "external_comms",
    attribution:
      "Tool initiates external network egress — HTTP, webhook, " +
      "email, IM — the destination leg of the exfiltration chain.",
    min_confidence: 0.5,
  },
};

/**
 * The confidence the F1 builder reports is the minimum of the three
 * legs' maximum capability confidences. This threshold is *separate* from
 * the per-leg `min_confidence` above: a node only contributes to a leg if
 * its capability confidence clears `min_confidence`; a trifecta only
 * fires if all three legs have at least one contributing node.
 */
export const TRIFECTA_MIN_LEG_CONFIDENCE = 0.5;

/**
 * Charter confidence cap. Capability classification is probabilistic and
 * graph reachability is inferred (not observed at runtime), so F1 cannot
 * claim 0.99 even with three strong legs.
 */
export const F1_CONFIDENCE_CAP = 0.9;
