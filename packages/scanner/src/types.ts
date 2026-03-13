/**
 * P9 — Scanner Engine Engineer
 * Types for the MCP Sentinel scan pipeline orchestrator.
 *
 * These types flow through the full pipeline:
 *   Discovery → Source Fetch → Dependency Audit → Connection → Analysis → Scoring → Persistence
 */

// ─── Scan Run Configuration ───────────────────────────────────────────────────

export interface ScanOptions {
  /** Scan a specific server by UUID (bypasses queue selection) */
  serverId?: string;
  /** Re-scan servers whose last completed scan is older than staleDays */
  rescan?: boolean;
  /** Days before a completed scan is considered stale (used with rescan, default: 7) */
  staleDays?: number;
  /** Maximum number of concurrent server scans (default: 5) */
  concurrency?: number;
  /** Maximum servers to scan in this run (default: 100) */
  limit?: number;
  /** List servers queued for scanning without executing any scans */
  dryRun?: boolean;
  /** Absolute path to the rules directory (default: project root /rules) */
  rulesDir?: string;
}

// ─── Per-Server Result ────────────────────────────────────────────────────────

export interface ScanStages {
  /** GitHub source code was successfully fetched */
  source_fetched: boolean;
  /** A live MCP connection was attempted (endpoint was discovered) */
  connection_attempted: boolean;
  /** The live MCP connection succeeded and tools were enumerated */
  connection_succeeded: boolean;
  /** OSV dependency CVE audit was executed */
  dependencies_audited: boolean;
}

export interface ScanServerResult {
  server_id: string;
  server_name: string;
  /** Whether the scan completed without a fatal error */
  success: boolean;
  findings_count: number;
  /** Composite security score (0–100), null if scan failed before scoring */
  score: number | null;
  /** Error message if success=false */
  error: string | null;
  elapsed_ms: number;
  /** Which pipeline stages completed for this server */
  stages: ScanStages;
}

// ─── Aggregate Run Stats ──────────────────────────────────────────────────────

export interface ScanRunStats {
  total: number;
  succeeded: number;
  failed: number;
  elapsed_ms: number;
  /** Sum of findings across all successfully scanned servers */
  findings_total: number;
  per_server: ScanServerResult[];
}

// ─── Source Fetcher Types ─────────────────────────────────────────────────────

/** Raw dependency before CVE enrichment — direct from package manifest */
export interface RawDependency {
  name: string;
  version: string | null;
  ecosystem: "npm" | "pypi";
}

/** Dependency enriched with live CVE data from the OSV database */
export interface EnrichedDependency {
  name: string;
  version: string | null;
  ecosystem: "npm" | "pypi";
  has_known_cve: boolean;
  cve_ids: string[];
  /** ISO 8601 date of last package update, if available */
  last_updated: Date | null;
}
