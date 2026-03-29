#!/usr/bin/env node
/**
 * Attack Graph CLI — DB-integrated kill chain synthesis.
 *
 * Reads scored servers from the database, runs risk-matrix analysis to build
 * a capability graph and detect cross-server edges, then synthesizes multi-step
 * attack chains via template-driven kill chain matching.
 *
 * Usage:
 *   pnpm attack-graph                        Analyse all scored servers
 *   pnpm attack-graph --limit=500            Limit server set size
 *   pnpm attack-graph --json                 JSON output for CI
 *   pnpm attack-graph --dry-run              Analyse without persisting chains
 *   pnpm attack-graph --with-findings        Enrich chains with single-server findings
 *
 * Environment variables:
 *   DATABASE_URL   PostgreSQL connection string (required)
 *
 * Exit codes:
 *   0  — aggregate risk is none, low, medium, or high
 *   1  — aggregate risk is critical
 */

import process from "node:process";
import pg from "pg";
import pino from "pino";
import { DatabaseQueries } from "@mcp-sentinel/database";
import { RiskMatrixAnalyzer, buildCapabilityGraph } from "@mcp-sentinel/risk-matrix";
import { AttackGraphEngine } from "./engine.js";
import type { AttackChain } from "./types.js";

const logger = pino({ name: "attack-graph:cli" });

// ── Argument parsing ──────────────────────────────────────────────────────────

function parseLimit(args: string[]): number {
  for (const arg of args) {
    if (arg.startsWith("--limit=")) {
      const raw = arg.slice("--limit=".length);
      const parsed = parseInt(raw, 10);
      if (Number.isNaN(parsed) || parsed <= 0) {
        logger.error({ raw }, "--limit must be a positive integer");
        process.exit(1);
      }
      return parsed;
    }
  }
  return 5000;
}

function hasFlag(args: string[], flag: string): boolean {
  return args.includes(flag);
}

// ── Chain summary builder ─────────────────────────────────────────────────────

function chainSummary(chain: AttackChain) {
  return {
    chain_id: chain.chain_id,
    kill_chain_id: chain.kill_chain_id,
    kill_chain_name: chain.kill_chain_name,
    exploitability: chain.exploitability.overall,
    rating: chain.exploitability.rating,
    steps: chain.steps.length,
    servers: chain.steps.map((s) => s.server_name),
    owasp: chain.owasp_refs,
    mitre: chain.mitre_refs,
    mitigations: chain.mitigations.length,
    narrative: chain.narrative,
  };
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  // ── Validate DATABASE_URL ────────────────────────────────────────────────
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    logger.error("DATABASE_URL environment variable is required");
    process.exit(1);
  }

  // ── Parse flags ──────────────────────────────────────────────────────────
  const limit = parseLimit(args);
  const jsonMode = hasFlag(args, "--json");
  const dryRun = hasFlag(args, "--dry-run");
  const withFindings = hasFlag(args, "--with-findings");

  // ── Database connection ──────────────────────────────────────────────────
  const isLocal =
    databaseUrl.includes("localhost") || databaseUrl.includes("127.0.0.1");
  const pool = new pg.Pool({
    connectionString: databaseUrl,
    ssl: isLocal ? false : { rejectUnauthorized: false },
  });

  try {
    const db = new DatabaseQueries(pool);
    const startMs = Date.now();

    // ── 1. Load servers with tools ───────────────────────────────────────
    logger.info({ limit }, "Loading servers from database");
    const servers = await db.getServersWithTools(limit);
    logger.info({ count: servers.length }, "Servers loaded");

    if (servers.length === 0) {
      logger.warn("No scored servers found — run the scan pipeline first");
      if (jsonMode) {
        console.log(
          JSON.stringify({
            servers_analysed: 0,
            risk_edges: 0,
            patterns_fired: 0,
            chains_detected: 0,
            critical_chains: 0,
            high_chains: 0,
            aggregate_risk: "none",
            config_id: "",
            chains: [],
            summary: "No servers to analyse.",
            elapsed_ms: Date.now() - startMs,
            dry_run: dryRun,
            chains_persisted: 0,
          })
        );
      }
      process.exitCode = 0;
      return;
    }

    // ── 2. Run risk-matrix analysis ──────────────────────────────────────
    logger.info("Running RiskMatrixAnalyzer across server set");
    const riskAnalyzer = new RiskMatrixAnalyzer();
    const riskReport = riskAnalyzer.analyze(servers);

    logger.info(
      {
        edges: riskReport.edges.length,
        patterns: riskReport.patterns_detected.length,
      },
      "Risk matrix analysis complete"
    );

    if (riskReport.edges.length === 0) {
      logger.info("No cross-server risk edges detected");
    }

    // ── 3. Optionally fetch single-server findings ───────────────────────
    let serverFindings: Record<string, string[]> | undefined;
    if (withFindings) {
      const nodeIds = [
        ...new Set(
          riskReport.edges.flatMap((e: { from_server_id: string; to_server_id: string }) => [e.from_server_id, e.to_server_id])
        ),
      ];
      if (nodeIds.length > 0) {
        serverFindings = await db.getFindingRuleIdsByServerIds(nodeIds);
        logger.info(
          { servers_with_findings: Object.keys(serverFindings!).length },
          "Findings loaded"
        );
      } else {
        logger.info("0 servers with findings (no risk edges)");
      }
    }

    // ── 4. Build attack graph ────────────────────────────────────────────
    logger.info("Synthesizing multi-step attack chains");
    const nodes = buildCapabilityGraph(servers);
    const engine = new AttackGraphEngine();
    const report = engine.analyze({
      nodes,
      edges: riskReport.edges,
      patterns_detected: riskReport.patterns_detected,
      server_findings: serverFindings,
    });

    logger.info(
      {
        chains: report.chain_count,
        critical: report.critical_chains,
        high: report.high_chains,
        aggregate: report.aggregate_risk,
      },
      "Attack graph analysis complete"
    );

    // ── 5. Persist chains ────────────────────────────────────────────────
    let chainsPersisted = 0;
    if (!dryRun && report.chains.length > 0) {
      await db.insertAttackChains(
        report.config_id,
        report.chains.map((c) => ({
          chain_id: c.chain_id,
          kill_chain_id: c.kill_chain_id,
          kill_chain_name: c.kill_chain_name,
          steps: c.steps as unknown[],
          exploitability_overall: c.exploitability.overall,
          exploitability_rating: c.exploitability.rating,
          exploitability_factors: c.exploitability.factors as unknown[],
          narrative: c.narrative,
          mitigations: c.mitigations as unknown[],
          owasp_refs: c.owasp_refs,
          mitre_refs: c.mitre_refs,
          evidence: c.evidence as unknown,
        }))
      );
      chainsPersisted = report.chains.length;
      logger.info({ persisted: chainsPersisted }, "Chains persisted to database");
    }

    const elapsedMs = Date.now() - startMs;

    // ── 6. Output ────────────────────────────────────────────────────────
    if (jsonMode) {
      console.log(
        JSON.stringify({
          servers_analysed: report.server_count,
          risk_edges: riskReport.edges.length,
          patterns_fired: riskReport.patterns_detected.length,
          chains_detected: report.chain_count,
          critical_chains: report.critical_chains,
          high_chains: report.high_chains,
          aggregate_risk: report.aggregate_risk,
          config_id: report.config_id,
          chains: report.chains.map(chainSummary),
          summary: report.summary,
          elapsed_ms: elapsedMs,
          dry_run: dryRun,
          chains_persisted: chainsPersisted,
        })
      );
    } else {
      console.log("");
      console.log("═══════════════════════════════════════════════════════");
      console.log("  MCP Sentinel — Attack Graph Analysis");
      console.log("═══════════════════════════════════════════════════════");
      console.log("");
      console.log(`  Servers analysed:   ${report.server_count}`);
      console.log(`  Risk edges:         ${riskReport.edges.length}`);
      console.log(`  Patterns fired:     ${riskReport.patterns_detected.length}`);
      console.log(`  Chains detected:    ${report.chain_count}`);
      console.log(`  Critical chains:    ${report.critical_chains}`);
      console.log(`  High chains:        ${report.high_chains}`);
      console.log(`  Aggregate risk:     ${report.aggregate_risk.toUpperCase()}`);
      console.log(`  Elapsed:            ${elapsedMs}ms`);
      if (dryRun) {
        console.log(`  Mode:               DRY RUN (no DB writes)`);
      } else if (chainsPersisted > 0) {
        console.log(`  Chains persisted:   ${chainsPersisted}`);
      }
      console.log("");

      if (report.chains.length > 0) {
        console.log("── Attack Chains ──────────────────────────────────────");
        for (const chain of report.chains) {
          const s = chainSummary(chain);
          console.log("");
          console.log(
            `  [${s.rating.toUpperCase()}] ${s.kill_chain_name} (${s.chain_id})`
          );
          console.log(
            `    Exploitability: ${(s.exploitability * 100).toFixed(0)}%`
          );
          console.log(`    Steps: ${s.steps} | Mitigations: ${s.mitigations}`);
          console.log(`    Servers: ${s.servers.join(" → ")}`);
          console.log(`    ${s.narrative}`);
        }
        console.log("");
      }

      console.log(report.summary);
      console.log("");
    }

    // ── 7. Exit code ─────────────────────────────────────────────────────
    if (report.aggregate_risk === "critical") {
      process.exitCode = 1;
    }
  } finally {
    await pool.end();
  }
}

main().catch((err) => {
  logger.fatal(err, "Unhandled error in attack-graph CLI");
  process.exitCode = 2;
});

export { parseLimit, hasFlag, chainSummary, main };
