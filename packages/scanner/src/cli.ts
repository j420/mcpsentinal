#!/usr/bin/env node
/**
 * P9 — Scanner Engine Engineer
 * CLI entry point for the MCP Sentinel scan pipeline.
 *
 * Usage:
 *   pnpm scan                                  Scan all unscanned servers (up to --limit)
 *   pnpm scan --server=<uuid>                  Scan a specific server by ID
 *   pnpm scan --rescan                         Re-scan servers with stale scans
 *   pnpm scan --rescan --stale-days=3          Re-scan servers not scanned in 3 days
 *   pnpm scan --dry-run                        List servers to scan without scanning
 *   pnpm scan --concurrency=10                 Use 10 parallel scan workers
 *   pnpm scan --limit=500                      Scan up to 500 servers
 *   pnpm scan --json                           Output results as JSON (for CI)
 *   pnpm scan --rules-dir=/path/rules          Override rules directory
 *   pnpm scan --dynamic                        Enable dynamic testing (Layer 5 gated)
 *   pnpm scan --dynamic --dynamic-allowlist=<id1,id2>  Pre-approve server IDs
 *
 * Environment variables:
 *   DATABASE_URL     PostgreSQL connection string (required)
 *   GITHUB_TOKEN     GitHub personal access token (strongly recommended)
 *                    Without this, GitHub API is limited to 60 req/hour.
 *                    Get one at https://github.com/settings/tokens
 */

import { parseArgs } from "node:util";
import process from "node:process";
import pg from "pg";
import pino from "pino";
import { DatabaseQueries } from "@mcp-sentinel/database";
import { ScanPipeline } from "./pipeline.js";
import type { ScanMode, ScanRunStats } from "./types.js";

const logger = pino({ name: "scanner:cli" });

async function main(): Promise<void> {
  const { values } = parseArgs({
    options: {
      server: { type: "string" },
      mode: { type: "string", default: "incremental" },   // incremental | rescan-failed | full
      "batch-size": { type: "string" },                   // alias for --limit (used by scan.yml)
      rescan: { type: "boolean", default: false },         // deprecated: use --mode=full
      "stale-days": { type: "string", default: "7" },
      concurrency: { type: "string", default: "5" },
      limit: { type: "string", default: "100" },
      "dry-run": { type: "boolean", default: false },
      json: { type: "boolean", default: false },
      "rules-dir": { type: "string" },
      dynamic: { type: "boolean", default: false },        // Layer 5 gated dynamic testing
      "dynamic-allowlist": { type: "string" },             // comma-separated server IDs
    },
    strict: true,
  });

  const VALID_MODES: ScanMode[] = ["incremental", "rescan-failed", "full"];
  const rawMode = values.mode ?? "incremental";
  if (!VALID_MODES.includes(rawMode as ScanMode)) {
    logger.error({ mode: rawMode }, `Invalid --mode. Must be one of: ${VALID_MODES.join(", ")}`);
    process.exit(1);
  }
  const mode = rawMode as ScanMode;

  // --batch-size is the canonical name used by scan.yml; --limit is the legacy name
  const effectiveLimit = values["batch-size"] ?? values.limit ?? "100";

  // ── Validate environment ───────────────────────────────────────────────────
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    logger.error("DATABASE_URL environment variable is required");
    logger.error("Example: DATABASE_URL=postgresql://user:pass@localhost:5432/mcp_sentinel pnpm scan");
    process.exit(1);
  }

  if (!process.env.GITHUB_TOKEN) {
    logger.warn(
      "GITHUB_TOKEN not set — source code analysis will be limited to 60 GitHub API requests/hour. " +
        "Set GITHUB_TOKEN for full scanning capability."
    );
  }

  // ── Initialize DB + pipeline ───────────────────────────────────────────────
  const pool = new pg.Pool({ connectionString: databaseUrl });

  // Handle idle connection resets from Railway proxy — without this handler,
  // ECONNRESET on an idle pooled connection crashes the entire process.
  pool.on("error", (err) => {
    logger.warn({ err: err.message }, "Idle pool connection error — pool will reconnect");
  });

  const db = new DatabaseQueries(pool);

  try {
    const pipeline = new ScanPipeline(db, {
      rulesDir: values["rules-dir"],
    });

    const dynamicAllowlist = values["dynamic-allowlist"]
      ? values["dynamic-allowlist"].split(",").map((id) => id.trim()).filter(Boolean)
      : [];

    if (values.dynamic) {
      logger.info(
        { allowlist_count: dynamicAllowlist.length },
        "Dynamic testing enabled — will probe consenting servers with Layer 5 gated capability"
      );
    }

    const stats = await pipeline.run({
      serverId: values.server,
      mode,
      staleDays: parseInt(values["stale-days"] ?? "7", 10),
      concurrency: parseInt(values.concurrency ?? "5", 10),
      limit: parseInt(effectiveLimit, 10),
      dryRun: values["dry-run"] ?? false,
      dynamic: values.dynamic ?? false,
      dynamicAllowlist,
    });

    // ── Output ─────────────────────────────────────────────────────────────
    if (values.json) {
      process.stdout.write(JSON.stringify(stats, null, 2) + "\n");
    } else {
      printHumanReadable(stats);
    }

    // Exit 1 only if there were servers to scan AND the failure rate is too high.
    // Zero servers to scan (incremental mode, all already scanned) is NOT a failure.
    // Individual server failures (timeouts, bad endpoints) are expected and
    // should not fail the workflow job — that would make scan.yml unreliable.
    const failureRate = stats.total > 0 ? stats.failed / stats.total : 0;
    const criticalFailure = stats.total > 0 && (stats.succeeded === 0 || failureRate > 0.1);
    process.exitCode = criticalFailure ? 1 : 0;
  } finally {
    await pool.end();
  }
}

function printHumanReadable(stats: ScanRunStats): void {
  const elapsed = (stats.elapsed_ms / 1000).toFixed(1);
  const bar = "─".repeat(58);

  console.log(`\n${bar}`);
  console.log("  MCP SENTINEL — Scan Pipeline Complete");
  console.log(bar);
  console.log(`  Servers scanned : ${stats.total}`);
  console.log(`  Succeeded       : ${stats.succeeded}`);
  console.log(`  Failed          : ${stats.failed}`);
  console.log(`  Total findings  : ${stats.findings_total}`);
  console.log(`  Elapsed         : ${elapsed}s`);
  console.log(bar);

  if (stats.per_server.length > 0 && stats.per_server.length <= 50) {
    // Only print per-server table for manageable output sizes
    console.log("\n  Per-Server Results:");
    console.log(
      `  ${"Server".padEnd(40)} ${"Score".padEnd(8)} ${"Findings".padEnd(10)} ${"Time".padEnd(8)} Stages`
    );
    console.log("  " + "─".repeat(78));

    for (const r of stats.per_server) {
      const status = r.success ? "✓" : "✗";
      const name = r.server_name.substring(0, 38).padEnd(40);
      const score = (r.score !== null ? String(r.score) : "N/A").padEnd(8);
      const findings = String(r.findings_count).padEnd(10);
      const time = `${(r.elapsed_ms / 1000).toFixed(1)}s`.padEnd(8);

      const stageIcons = [
        r.stages.source_fetched ? "S" : "·",
        r.stages.dependencies_audited ? "D" : "·",
        r.stages.connection_succeeded ? "C" : r.stages.connection_attempted ? "c" : "·",
      ].join("");

      const errorNote = r.error && !r.success ? ` ← ${r.error.substring(0, 40)}` : "";
      console.log(`  ${status} ${name} ${score} ${findings} ${time} [${stageIcons}]${errorNote}`);
    }

    console.log("\n  Stage legend: S=source fetched  D=deps audited  C=connected  c=conn failed  ·=skipped");
  } else if (stats.per_server.length > 50) {
    console.log(
      `\n  (Per-server detail suppressed for ${stats.per_server.length} servers — use --json for full output)`
    );
  }

  console.log(`\n${bar}\n`);
}

main().catch((err) => {
  logger.error({ err }, "Fatal scanner error");
  process.exit(1);
});
