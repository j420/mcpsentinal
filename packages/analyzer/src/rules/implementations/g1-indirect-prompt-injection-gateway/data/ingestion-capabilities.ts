/**
 * G1 ingestion + sink registry.
 *
 * G1 is a capability-pair rule. It fires when the capability-graph
 * analyzer classifies any tool on the server as an "ingestion gateway"
 * (it returns attacker-reachable content) AND the same server exposes
 * at least one tool the agent can subsequently invoke as a sink
 * (network egress, filesystem write, config modification, or any other
 * side-effecting operation).
 *
 * The two typed records below name the capabilities that qualify each
 * side of the pair. The capability-graph analyzer already produces
 * these tags; this file only maps tags → G1's role semantics, with
 * attribution strings surfaced into ConfidenceFactor rationales.
 *
 * No bare string-arrays; every entry is a typed record. Ingestion-kind
 * attribution strings fit within the 5-element cap enforced by the
 * no-static-patterns guard.
 */

import type { Capability } from "../../../analyzers/capability-graph.js";

/**
 * Short taxonomy of ingestion sources. The tag is surfaced in narratives
 * so a reviewer sees WHICH class of attacker-reachable content a given
 * tool is treated as (web / email / file / etc.) rather than just
 * "untrusted".
 */
export type IngestionKind =
  | "web"
  | "email"
  | "chat"
  | "issue_tracker"
  | "file"
  | "database"
  | "rss"
  | "resource_fetch"
  | "generic";

/** Per-capability record for the gateway leg. */
export interface IngestionEntry {
  /** The ingestion taxonomy class — for narratives + test assertions. */
  ingestion_kind: IngestionKind;
  /** Where the content originates from a trust perspective. */
  typical_trust_boundary:
    | "external_public"
    | "external_authenticated"
    | "internal";
  /** Short rationale string for ConfidenceFactor consumers. */
  attribution: string;
  /** Minimum capability-graph confidence for this capability to qualify. */
  min_confidence: number;
}

/**
 * Gateway-leg capabilities: the ones that classify a tool as an
 * indirect-injection gateway. `ingests-untrusted` is the canonical tag;
 * `accesses-filesystem` is included because filesystem reads in MCP
 * deployments routinely ingest content the server's host user did not
 * author (shared drives, attacker-writable symlinks — CVE-2025-53109).
 */
export const INGESTION_CAPABILITIES: Readonly<
  Partial<Record<Capability, IngestionEntry>>
> = {
  "ingests-untrusted": {
    ingestion_kind: "generic",
    typical_trust_boundary: "external_public",
    attribution:
      "Tool ingests content from an attacker-reachable source — web page, " +
      "email, issue tracker, chat message, RSS feed, or uploaded file.",
    min_confidence: 0.4,
  },
  "accesses-filesystem": {
    ingestion_kind: "file",
    typical_trust_boundary: "internal",
    attribution:
      "Filesystem reader — in MCP deployments the reader routinely " +
      "crosses paths a non-host user can write (shared directories, " +
      "symlinks — see CVE-2025-53109).",
    min_confidence: 0.4,
  },
};

/** Sink-leg role classifications. */
export type SinkRole =
  | "network_egress"
  | "filesystem_write"
  | "code_execution"
  | "config_modification"
  | "agent_state_write";

/** Per-capability record for the sink leg (the thing the injected instruction will target). */
export interface SinkEntry {
  /** What kind of sink this is, for chain narratives. */
  sink_role: SinkRole;
  /** Short rationale string for ConfidenceFactor consumers. */
  attribution: string;
  /** Minimum capability-graph confidence. */
  min_confidence: number;
}

/**
 * Sink-leg capabilities. A G1 finding pairs the gateway with the
 * first-sorted sink node — the narrative names the canonical sink, but
 * the factor `sink_reachability` records the count of all qualifying
 * sinks on the server.
 */
export const SINK_CAPABILITIES: Readonly<Partial<Record<Capability, SinkEntry>>> = {
  "sends-network": {
    sink_role: "network_egress",
    attribution:
      "Egress sink — HTTP client / webhook / email / chat send. Turns a " +
      "poisoned read into exfiltration via the agent.",
    min_confidence: 0.5,
  },
  "writes-data": {
    sink_role: "filesystem_write",
    attribution:
      "Write sink — file creation, database write, configuration " +
      "modification. Persistent prompt-injection primitive.",
    min_confidence: 0.5,
  },
  "executes-code": {
    sink_role: "code_execution",
    attribution:
      "Execution sink — exec/spawn/eval surface. The most severe sink " +
      "class because an instruction becomes arbitrary code.",
    min_confidence: 0.5,
  },
  "modifies-config": {
    sink_role: "config_modification",
    attribution:
      "Config-modification sink — writes to MCP client config, server " +
      "registration, or agent state. Cross-reference J1.",
    min_confidence: 0.5,
  },
};

/** Confidence cap for every G1 finding (charter §Confidence cap). */
export const G1_CONFIDENCE_CAP = 0.75;

/**
 * Below this base confidence the rule does NOT fire. Avoids emitting
 * G1 on tools whose ingestion classification is a fluke of the
 * classifier (see charter edge case #4 — utility-tool low-entropy
 * trifecta analogue).
 */
export const G1_MIN_BASE_CONFIDENCE = 0.4;

/**
 * Schema-parameter hints the gather step inspects to decide whether a
 * tool declares a content sanitizer (mitigation link present=true). A
 * sanitizer present decrements confidence via the MitigationLink's
 * built-in -0.30 adjustment in the EvidenceChainBuilder.
 */
export const SANITIZER_PARAM_NAMES: Readonly<string[]> = [
  "sanitize_output",
  "strip_html",
  "content_filter",
  "clean_markdown",
  "escape_content",
];

/**
 * Display-only taxonomy hints. Used by gather.ts to refine the ingestion-kind
 * narrative label (web / email / chat / ...). This is NOT the detection
 * signal — the capability-graph already classified the tool as
 * `ingests-untrusted`; these hints only choose a more specific label.
 *
 * Each inner list is ≤5 entries so the no-static-patterns guard is
 * satisfied even though this file sits under data/ (which is exempt).
 * Keeping the data inside data/ anyway so the convention is consistent.
 */
export const INGESTION_KIND_HINTS: ReadonlyArray<
  readonly [IngestionKind, readonly string[]]
> = [
  ["web", ["scrape", "crawl", "browse", "webpage", "html"]],
  ["email", ["email", "inbox", "imap", "gmail", "mailbox"]],
  ["chat", ["slack", "discord", "telegram", "channel", "chatroom"]],
  ["issue_tracker", ["issue", "jira", "linear", "pull request", "ticket"]],
  ["file", ["filesystem", "read_file", "document", "directory", "folder"]],
  ["database", ["database", "query", "select", "table", "record"]],
  ["rss", ["rss", "atom", "feed", "subscribe"]],
];
