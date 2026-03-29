#!/usr/bin/env node
/**
 * Attack Graph CLI — multi-step kill chain synthesis across MCP server configs.
 *
 * Reads all scored servers + their tools from the DB, builds a capability graph
 * via RiskMatrixAnalyzer, feeds the edges + nodes into AttackGraphEngine, persists
 * discovered chains (append-only, ADR-008), and outputs results.
 *
 * This is the database-integrated entry point for attack-graph analysis. The engine
 * itself is pure (no I/O); this CLI handles all database reads and writes.
 *
 * Usage:
 *   pnpm attack-graph                    Analyse all scored servers (up to 5000)
 *   pnpm attack-graph --limit=500        Limit server set size
 *   pnpm attack-graph --json             JSON output for CI
 *   pnpm attack-graph --dry-run          Analyse without writing anything to DB
 *   pnpm attack-graph --with-findings    Include per-server findings for scoring boost
 *
 * Environment variables:
 *   DATABASE_URL   PostgreSQL connection string (required)
 */

import { parseArgs } from "node:util";
import process from "node:process";
import pg from "pg";
import pino from "pino";
import { DatabaseQueries } from "@mcp-sentinel/database";
import { RiskMatrixAnalyzer, buildCapabilityGraph } from "@mcp-sentinel/risk-matrix";
import { AttackGraphEngine } from "./index.js";
import type { AttackGraphReport, AttackChain } from "./types.js";

const logger = pino({ name: "attack-graph:cli" });

// ── Exported helpers (testable independently) ─────────────────────────────

/** Parse --limit=N from raw argv, defaulting to 5000. Exits on invalid. */
export function parseLimit(args: string[]): number {
  const limitArg = args.find((a) => a.startsWith("--limit="));
  if (!limitArg) return 5000;
  const raw = limitArg.split("=")[1];
  const val = parseInt(raw, 10);
  if (Number.isNaN(val) || val <= 0) {
    logger.error({ limit: raw }, "Invalid --limit value, must be a positive integer");
    process.exit(1);
  }
  return val;
}

/** Check whether a flag is present in raw argv. */
export function hasFlag(args: string[], flag: string): boolean {
  return args.includes(flag);
}

export async function main(): Promise<void> {
  const { values } = parseArgs({
    options: {
      limit:           { type: "string",  default: "5000" },
      json:            { type: "boolean", default: false },
      "dry-run":       { type: "boolean", default: false },
      "with-findings": { type: "boolean", default: false },
    },
    strict: true,
  });

  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    logger.error("DATABASE_URL environment variable is required");
    process.exit(1);
  }

  const limit        = parseInt(values.limit ?? "5000", 10);
  const dryRun       = values["dry-run"]       ?? false;
  const jsonMode     = values.json             ?? false;
  const withFindings = values["with-findings"] ?? false;

  if (Number.isNaN(limit) || limit <= 0) {
    logger.error({ limit: values.limit }, "Invalid --limit value, must be a positive integer");
    process.exit(1);
  }

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
      if (jsonMode) {
        process.stdout.write(JSON.stringify({
          servers_analysed: 0,
          chains_detected: 0,
          critical_chains: 0,
          high_chains: 0,
          aggregate_risk: "none",
          summary: "No servers to analyze.",
          elapsed_ms: Date.now() - runStart,
          dry_run: dryRun,
        }, null, 2) + "\n");
      }
      process.exitCode = 0;
      return;
    }

    // ── 2. Build capability graph + run risk-matrix patterns ──────────────────
    // We run risk-matrix inline to get fresh edges and nodes. The attack-graph
    // engine needs both CapabilityNode[] and RiskEdge[] as input.
    logger.info("Running RiskMatrixAnalyzer to produce capability graph + risk edges");
    const riskAnalyzer = new RiskMatrixAnalyzer();
    const riskReport = riskAnalyzer.analyze(servers);
    const nodes = buildCapabilityGraph(servers);

    logger.info(
      {
        edges:    riskReport.edges.length,
        patterns: riskReport.patterns_detected.length,
        nodes:    nodes.length,
      },
      "Risk matrix complete — feeding into attack-graph engine"
    );

    if (riskReport.edges.length === 0) {
      logger.info("No cross-server risk edges detected — no chains possible");
      const elapsed = Date.now() - runStart;
      if (jsonMode) {
        process.stdout.write(JSON.stringify({
          servers_analysed: servers.length,
          chains_detected: 0,
          critical_chains: 0,
          high_chains: 0,
          aggregate_risk: "none",
          config_id: riskReport.config_id,
          summary: `Analysed ${servers.length} servers. No cross-server risk edges detected. No kill chains possible.`,
          elapsed_ms: elapsed,
          dry_run: dryRun,
        }, null, 2) + "\n");
      } else {
        printHumanReadable(
          { generated_at: new Date().toISOString(), config_id: riskReport.config_id, server_count: servers.length, chains: [], chain_count: 0, critical_chains: 0, high_chains: 0, aggregate_risk: "none", summary: "No cross-server risk edges detected." },
          elapsed,
          dryRun,
          0
        );
      }
      process.exitCode = 0;
      return;
    }

    // ── 3. Optionally load per-server findings for scoring boost ──────────────
    let serverFindings: Record<string, string[]> | undefined = undefined;
    if (withFindings) {
      logger.info("Loading per-server findings for scoring boost");
      const serverIds = nodes.map((n) => n.server_id);
      const loaded = await db.getFindingRuleIdsByServerIds(serverIds);
      serverFindings = loaded;
      const serversWithFindings = Object.keys(loaded).length;
      const totalFindings = Object.values(loaded).reduce((sum, ids) => sum + ids.length, 0);
      logger.info({ serversWithFindings, totalFindings }, "Findings loaded");
    }

    // ── 4. Run attack-graph engine ───────────────────────────────────────────
    logger.info("Running AttackGraphEngine — synthesizing kill chains");
    const engine = new AttackGraphEngine();
    const report = engine.analyze({
      nodes,
      edges: riskReport.edges,
      patterns_detected: riskReport.patterns_detected,
      server_findings: serverFindings,
    });

    logger.info(
      {
        chains:          report.chain_count,
        critical_chains: report.critical_chains,
        high_chains:     report.high_chains,
        aggregate_risk:  report.aggregate_risk,
        config_id:       report.config_id,
      },
      "Attack-graph synthesis complete"
    );

    // ── 5. Persist chains (append-only, ADR-008) ─────────────────────────────
    let chainsPersisted = 0;
    if (!dryRun && report.chains.length > 0) {
      logger.info({ chains: report.chains.length }, "Persisting attack chains to DB");
      await db.insertAttackChains(
        report.config_id,
        report.chains.map((c) => ({
          chain_id:                c.chain_id,
          kill_chain_id:           c.kill_chain_id,
          kill_chain_name:         c.kill_chain_name,
          steps:                   c.steps as unknown[],
          exploitability_overall:  c.exploitability.overall,
          exploitability_rating:   c.exploitability.rating,
          exploitability_factors:  c.exploitability.factors as unknown[],
          narrative:               c.narrative,
          mitigations:             c.mitigations as unknown[],
          owasp_refs:              c.owasp_refs,
          mitre_refs:              c.mitre_refs,
          evidence:                c.evidence as unknown,
        }))
      );
      chainsPersisted = report.chains.length;
      logger.info({ persisted: chainsPersisted }, "Attack chains persisted");
    } else if (dryRun) {
      logger.info("Dry run — skipping DB writes");
    }

    const elapsed = Date.now() - runStart;

    // ── 6. Output ────────────────────────────────────────────────────────────
    if (jsonMode) {
      process.stdout.write(
        JSON.stringify({
          servers_analysed: report.server_count,
          risk_edges:       riskReport.edges.length,
          patterns_fired:   riskReport.patterns_detected,
          chains_detected:  report.chain_count,
          critical_chains:  report.critical_chains,
          high_chains:      report.high_chains,
          aggregate_risk:   report.aggregate_risk,
          config_id:        report.config_id,
          chains:           report.chains.map(chainSummary),
          summary:          report.summary,
          elapsed_ms:       elapsed,
          dry_run:          dryRun,
          chains_persisted: chainsPersisted,
        }, null, 2) + "\n"
      );
    } else {
      printHumanReadable(report, elapsed, dryRun, chainsPersisted);
    }

    // Fail CI if critical kill chains were found
    if (report.aggregate_risk === "critical") {
      process.exitCode = 1;
    }
  } finally {
    await pool.end();
  }
}

// ── Human-readable output ──────────────────────────────────────────────────

function printHumanReadable(
  report: AttackGraphReport,
  elapsed: number,
  dryRun: boolean,
  chainsPersisted: number
): void {
  const bar = "\u2500".repeat(64);
  const riskIcon: Record<string, string> = {
    none:     "\u2705",
    low:      "\uD83D\uDFE1",
    medium:   "\uD83D\uDFE0",
    high:     "\uD83D\uDD34",
    critical: "\uD83D\uDEA8",
  };

  console.log(`\n${bar}`);
  console.log("  MCP SENTINEL \u2014 Attack Chain Synthesis");
  console.log(bar);
  console.log(`  Servers analysed  : ${report.server_count}`);
  console.log(`  Kill chains found : ${report.chain_count}`);
  console.log(`  Critical chains   : ${report.critical_chains}`);
  console.log(`  High chains       : ${report.high_chains}`);
  console.log(`  Aggregate risk    : ${riskIcon[report.aggregate_risk] ?? "\u2753"} ${report.aggregate_risk.toUpperCase()}`);
  console.log(`  Chains persisted  : ${chainsPersisted}${dryRun ? " (dry-run)" : ""}`);
  console.log(`  Elapsed           : ${(elapsed / 1000).toFixed(1)}s`);
  console.log(bar);

  if (report.chains.length > 0) {
    console.log("\n  Detected Kill Chains:");

    // Sort by exploitability descending, show top 10
    const sorted = [...report.chains].sort(
      (a, b) => b.exploitability.overall - a.exploitability.overall
    );
    const display = sorted.slice(0, 10);

    for (const chain of display) {
      const icon = chain.exploitability.rating === "critical"
        ? "\uD83D\uDEA8"
        : chain.exploitability.rating === "high"
          ? "\uD83D\uDD34"
          : chain.exploitability.rating === "medium"
            ? "\uD83D\uDFE0"
            : "\uD83D\uDFE1";
      const pct = (chain.exploitability.overall * 100).toFixed(0);
      console.log(`\n  ${icon} ${chain.kill_chain_id} \u2014 ${chain.kill_chain_name} (${pct}% exploitability)`);
      console.log(`     Steps: ${chain.steps.map((s) => `${s.server_name}[${s.role}]`).join(" \u2192 ")}`);
      console.log(`     OWASP: ${chain.owasp_refs.join(", ") || "none"}`);
      console.log(`     MITRE: ${chain.mitre_refs.join(", ") || "none"}`);

      // Show first mitigation
      if (chain.mitigations.length > 0) {
        const m = chain.mitigations[0];
        const effect = m.effect === "breaks_chain" ? "BREAKS CHAIN" : "reduces risk";
        console.log(`     Fix:   ${m.action} on ${m.target_server_name} (${effect})`);
        if (chain.mitigations.length > 1) {
          console.log(`            + ${chain.mitigations.length - 1} more mitigation${chain.mitigations.length - 1 > 1 ? "s" : ""}`);
        }
      }
    }

    if (report.chains.length > 10) {
      console.log(`\n  ... and ${report.chains.length - 10} more chains (use --json for full output)`);
    }
  }

  console.log(`\n  ${report.summary}`);
  console.log(`${bar}\n`);
}

// ── JSON chain summary (compact) ───────────────────────────────────────────

export function chainSummary(chain: AttackChain) {
  return {
    chain_id:        chain.chain_id,
    kill_chain_id:   chain.kill_chain_id,
    kill_chain_name: chain.kill_chain_name,
    exploitability:  chain.exploitability.overall,
    rating:          chain.exploitability.rating,
    steps:           chain.steps.length,
    servers:         chain.steps.map((s) => ({ id: s.server_id, name: s.server_name, role: s.role })),
    owasp:           chain.owasp_refs,
    mitre:           chain.mitre_refs,
    mitigations:     chain.mitigations.length,
    narrative:       chain.narrative,
  };
}

/* istanbul ignore next -- auto-execute only when run directly (not under test) */
if (!process.env.VITEST) {
  main().catch((err) => {
    logger.error({ err }, "Fatal attack-graph error");
    process.exit(1);
  });
}
