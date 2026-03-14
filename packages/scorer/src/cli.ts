#!/usr/bin/env node
/**
 * Scorer CLI — recomputes composite security scores from stored findings.
 *
 * Usage:
 *   pnpm score                    Recompute scores for all servers with completed scans
 *   pnpm score --limit=500        Score up to 500 servers
 *   pnpm score --json             JSON output for CI
 *   pnpm score --rules-dir=/path  Override rules directory
 *
 * This is a standalone recomputation pass — it re-scores servers from their
 * stored findings without re-running the scan pipeline. Use after:
 *   - Adding or modifying detection rules (score values change)
 *   - A scan run where the scoring step failed
 *
 * The insertScore() call uses ON CONFLICT DO UPDATE, so re-running is safe.
 *
 * Environment variables:
 *   DATABASE_URL  PostgreSQL connection string (required)
 */

import { parseArgs } from "node:util";
import path from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";
import pino from "pino";
import { DatabaseQueries } from "@mcp-sentinel/database";
import { loadRules, getRulesVersion } from "@mcp-sentinel/analyzer";
import { computeScore } from "./scorer.js";

const logger = pino({ name: "scorer:cli" });

// Resolve rules directory relative to the monorepo root.
// __dirname is packages/scorer/src/ → ../../../rules resolves to <root>/rules
const __dirname = fileURLToPath(new URL(".", import.meta.url));
const DEFAULT_RULES_DIR = path.resolve(__dirname, "../../../rules");

async function main(): Promise<void> {
  const { values } = parseArgs({
    options: {
      "rules-dir": { type: "string" },
      limit: { type: "string", default: "1000" },
      json: { type: "boolean", default: false },
    },
    strict: true,
  });

  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    logger.error("DATABASE_URL environment variable is required");
    process.exit(1);
  }

  const rulesDir = values["rules-dir"] ?? DEFAULT_RULES_DIR;
  const limit = parseInt(values.limit ?? "1000", 10);

  // Load rules once — needed to map rule_id → category for sub-scores
  const rules = loadRules(rulesDir);
  const rulesVersion = getRulesVersion(rules);
  const ruleCategories = Object.fromEntries(rules.map((r) => [r.id, r.category]));
  logger.info({ rules: rules.length, rulesVersion, limit }, "Scorer starting");

  const pool = new pg.Pool({ connectionString: databaseUrl });
  const db = new DatabaseQueries(pool);

  try {
    const serverScans = await db.getServersWithCompletedScans(limit);
    logger.info({ servers: serverScans.length }, "Servers to score");

    let scored = 0;
    let failed = 0;

    for (const { server_id, scan_id } of serverScans) {
      try {
        const findings = await db.getFindingsByScanId(scan_id);
        const score = computeScore(findings, ruleCategories);
        await db.insertScore({
          server_id,
          scan_id,
          total_score: score.total_score,
          code_score: score.code_score,
          deps_score: score.deps_score,
          config_score: score.config_score,
          description_score: score.description_score,
          behavior_score: score.behavior_score,
          owasp_coverage: score.owasp_coverage,
          rules_version: rulesVersion,
        });
        scored++;
      } catch (err) {
        logger.error({ server_id, scan_id, err }, "Failed to score server");
        failed++;
      }
    }

    const result = { servers: serverScans.length, scored, failed, rules_version: rulesVersion };

    if (values.json) {
      process.stdout.write(JSON.stringify(result, null, 2) + "\n");
    } else {
      logger.info(result, "Score recomputation complete");
    }

    process.exitCode = failed > 0 ? 1 : 0;
  } finally {
    await pool.end();
  }
}

main().catch((err) => {
  logger.error({ err }, "Fatal scorer error");
  process.exit(1);
});
