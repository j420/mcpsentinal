#!/usr/bin/env node
/**
 * Report Generator CLI — generates "State of MCP Security" report from scan data.
 *
 * Usage:
 *   pnpm generate                    # Generate report to stdout
 *   pnpm generate --output report.md # Generate to file
 *   pnpm generate --json             # Output raw data as JSON
 *
 * Requires DATABASE_URL environment variable pointing to PostgreSQL.
 */

import pg from "pg";
import { writeFileSync } from "fs";
import pino from "pino";
import { computeEcosystemOverview } from "./ecosystem-stats.js";
import { computeTrendReport } from "./trend-analysis.js";
import { computeCategoryReport } from "./category-breakdown.js";
import { generateMarkdownReport } from "./generator.js";

const logger = pino({ name: "reports:cli" }, process.stderr);

async function main() {
  const args = process.argv.slice(2);
  const jsonMode = args.includes("--json");
  const outputIdx = args.indexOf("--output");
  const outputPath = outputIdx >= 0 ? args[outputIdx + 1] : null;

  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    console.error("ERROR: DATABASE_URL environment variable required.");
    console.error("Set it to your PostgreSQL connection string.");
    process.exit(1);
  }

  const pool = new pg.Pool({ connectionString: databaseUrl });

  try {
    logger.info("Connecting to database...");

    // Compute all report sections in parallel
    logger.info("Computing ecosystem overview...");
    const [ecosystem, trends, categories] = await Promise.all([
      computeEcosystemOverview(pool),
      computeTrendReport(pool),
      computeCategoryReport(pool),
    ]);

    logger.info(
      {
        servers_crawled: ecosystem.total_crawled,
        servers_scanned: ecosystem.total_scanned,
        total_findings: ecosystem.total_findings,
      },
      "Report data computed"
    );

    const reportData = {
      ecosystem,
      trends,
      categories,
      generated_at: new Date().toISOString().slice(0, 10),
    };

    if (jsonMode) {
      const json = JSON.stringify(reportData, null, 2);
      if (outputPath) {
        writeFileSync(outputPath, json);
        logger.info({ path: outputPath }, "JSON report written");
      } else {
        console.log(json);
      }
    } else {
      const markdown = generateMarkdownReport(reportData);
      if (outputPath) {
        writeFileSync(outputPath, markdown);
        logger.info({ path: outputPath }, "Markdown report written");
      } else {
        console.log(markdown);
      }
    }

    logger.info("Report generation complete");
  } catch (err) {
    logger.error({ err }, "Report generation failed");
    process.exit(1);
  } finally {
    await pool.end();
  }
}

main();
