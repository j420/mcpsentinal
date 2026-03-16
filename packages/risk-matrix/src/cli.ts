#!/usr/bin/env node
/**
 * P10 — Adversarial Tester
 * Risk Matrix CLI — cross-server attack path analysis against the full registry.
 *
 * Reads all scored servers from the DB, builds a capability graph, runs all
 * 12 cross-server patterns (P01–P12), persists the detected edges, and applies
 * score caps to servers involved in critical attack paths.
 *
 * This closes the gap identified in Layer 5: RiskMatrixAnalyzer was complete
 * but had no entry point wired to the database or the scan pipeline.
 *
 * Usage:
 *   pnpm risk-matrix                   Analyse all scored servers (up to 5000)
 *   pnpm risk-matrix --limit=500       Limit server set size
 *   pnpm risk-matrix --json            JSON output for CI
 *   pnpm risk-matrix --no-cap          Skip applying score caps to DB
 *   pnpm risk-matrix --dry-run         Analyse without writing anything to DB
 *
 * Environment variables:
 *   DATABASE_URL   PostgreSQL connection string (required)
 */

import { parseArgs } from "node:util";
import process from "node:process";
import pg from "pg";
import pino from "pino";
import { DatabaseQueries } from "@mcp-sentinel/database";
import { RiskMatrixAnalyzer } from "./index.js";

const logger = pino({ name: "risk-matrix:cli" });

async function main(): Promise<void> {
  const { values } = parseArgs({
    options: {
      limit:     { type: "string",  default: "5000" },
      json:      { type: "boolean", default: false },
      "no-cap":  { type: "boolean", default: false },
      "dry-run": { type: "boolean", default: false },
    },
    strict: true,
  });

  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    logger.error("DATABASE_URL environment variable is required");
    process.exit(1);
  }

  const limit    = parseInt(values.limit ?? "5000", 10);
  const dryRun   = values["dry-run"] ?? false;
  const noCap    = values["no-cap"]  ?? false;
  const jsonMode = values.json       ?? false;

  const isRemote =
    !databaseUrl.includes("localhost") && !databaseUrl.includes("127.0.0.1");
  const pool = new pg.Pool({
    connectionString: databaseUrl,
    ssl: isRemote ? { rejectUnauthorized: false } : false,
  });
  const db = new DatabaseQueries(pool);

  try {
    const runStart = Date.now();

    // ── 1. Load servers with tools ────────────────────────────────────────────
    logger.info({ limit }, "Loading servers from database");
    const servers = await db.getServersWithTools(limit);
    logger.info({ count: servers.length }, "Servers loaded");

    if (servers.length === 0) {
      logger.warn("No scored servers found — run the scan pipeline first");
      process.exitCode = 0;
      return;
    }

    // ── 2. Run cross-server analysis ──────────────────────────────────────────
    logger.info("Running RiskMatrixAnalyzer across server set");
    const analyzer = new RiskMatrixAnalyzer();
    const report = analyzer.analyze(servers);

    logger.info(
      {
        servers:          report.server_count,
        edges:            report.edges.length,
        patterns_fired:   report.patterns_detected.length,
        aggregate_risk:   report.aggregate_risk,
        score_caps:       Object.keys(report.score_caps).length,
        config_id:        report.config_id,
      },
      "Risk matrix analysis complete"
    );

    // ── 3. Persist edges ──────────────────────────────────────────────────────
    if (!dryRun && report.edges.length > 0) {
      logger.info({ edges: report.edges.length }, "Persisting risk edges to DB");
      await db.upsertRiskEdges(report.config_id, report.edges.map((e) => ({
        from_server_id:  e.from_server_id,
        to_server_id:    e.to_server_id,
        edge_type:       e.edge_type,
        pattern_id:      e.pattern_id ?? "UNKNOWN",
        severity:        e.severity,
        description:     e.description,
        owasp_category:  e.owasp ?? null,
        mitre_technique: e.mitre ?? null,
      })));
      logger.info("Risk edges persisted");
    } else if (dryRun) {
      logger.info("Dry run — skipping DB writes");
    }

    // ── 4. Apply score caps ───────────────────────────────────────────────────
    let capsApplied = 0;
    if (!dryRun && !noCap && Object.keys(report.score_caps).length > 0) {
      logger.info(
        { servers: Object.keys(report.score_caps).length },
        "Applying risk-matrix score caps"
      );
      capsApplied = await db.applyRiskScoreCaps(report.score_caps);
      logger.info({ applied: capsApplied }, "Score caps applied");
    }

    const elapsed = Date.now() - runStart;

    // ── 5. Output ─────────────────────────────────────────────────────────────
    if (jsonMode) {
      process.stdout.write(
        JSON.stringify({
          servers_analysed:  report.server_count,
          edges_detected:    report.edges.length,
          patterns_detected: report.patterns_detected,
          aggregate_risk:    report.aggregate_risk,
          score_caps:        report.score_caps,
          caps_applied:      capsApplied,
          config_id:         report.config_id,
          summary:           report.summary,
          elapsed_ms:        elapsed,
          dry_run:           dryRun,
        }, null, 2) + "\n"
      );
    } else {
      printHumanReadable(report, capsApplied, elapsed, dryRun);
    }

    // Fail CI if critical cross-server attack paths were found
    process.exitCode = report.aggregate_risk === "critical" ? 1 : 0;
  } finally {
    await pool.end();
  }
}

function printHumanReadable(
  report: Awaited<ReturnType<RiskMatrixAnalyzer["analyze"]>>,
  capsApplied: number,
  elapsed: number,
  dryRun: boolean
): void {
  const bar = "─".repeat(60);
  const riskColor = {
    none:     "✅",
    low:      "🟡",
    medium:   "🟠",
    high:     "🔴",
    critical: "🚨",
  }[report.aggregate_risk] ?? "❓";

  console.log(`\n${bar}`);
  console.log("  MCP SENTINEL — Cross-Server Risk Matrix");
  console.log(bar);
  console.log(`  Servers analysed  : ${report.server_count}`);
  console.log(`  Attack edges      : ${report.edges.length}`);
  console.log(`  Patterns fired    : ${report.patterns_detected.join(", ") || "none"}`);
  console.log(`  Aggregate risk    : ${riskColor} ${report.aggregate_risk.toUpperCase()}`);
  console.log(`  Score caps        : ${Object.keys(report.score_caps).length} servers (${capsApplied} updated${dryRun ? ", dry-run" : ""})`);
  console.log(`  Elapsed           : ${(elapsed / 1000).toFixed(1)}s`);
  console.log(bar);

  if (report.edges.length > 0) {
    console.log("\n  Top Attack Paths:");
    const critical = report.edges.filter((e) => e.severity === "critical");
    const high     = report.edges.filter((e) => e.severity === "high");
    const display  = [...critical, ...high].slice(0, 10);

    for (const edge of display) {
      const icon = edge.severity === "critical" ? "🚨" : "🔴";
      const pid = edge.pattern_id ?? "??";
      console.log(`  ${icon} [${pid}] ${edge.edge_type}`);
      console.log(`      ${edge.description.substring(0, 100)}`);
    }

    if (report.edges.length > 10) {
      console.log(`\n  ... and ${report.edges.length - 10} more edges (use --json for full output)`);
    }
  }

  console.log(`\n  ${report.summary}`);
  console.log(`${bar}\n`);
}

main().catch((err) => {
  logger.error({ err }, "Fatal risk-matrix error");
  process.exit(1);
});
