import pino from "pino";
import pg from "pg";
import { CrawlOrchestrator } from "./orchestrator.js";
import { DatabaseQueries } from "@mcp-sentinel/database";
import type { CrawlStats } from "./types.js";

const logger = pino({ name: "crawler:cli" });

async function main() {
  const args = process.argv.slice(2);
  const dryRun = args.includes("--dry-run");
  const sourceArg = args.find((a) => !a.startsWith("--"));
  const sources = sourceArg ? [sourceArg] : undefined;

  const orchestrator = new CrawlOrchestrator(sources);

  if (dryRun || !process.env.DATABASE_URL) {
    if (!process.env.DATABASE_URL) {
      logger.warn(
        "DATABASE_URL not set — running in dry-run mode (crawl only, no persistence)"
      );
    }
    const stats = await orchestrator.crawlAll();
    printSummary(stats);
    return;
  }

  const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
  const db = new DatabaseQueries(pool);

  try {
    const stats = await orchestrator.crawlAndPersist(db);
    printSummary(stats, stats.persisted, stats.persist_errors);
  } finally {
    await pool.end();
  }
}

function printSummary(
  stats: CrawlStats,
  persisted?: number,
  persistErrors?: number
) {
  console.log("\n=== Crawl Summary ===");
  console.log(`Total discovered: ${stats.total_discovered}`);
  console.log(`New unique:       ${stats.new_unique}`);

  if (persisted !== undefined) {
    console.log(`Upsert calls:     ${persisted} (includes cross-source enrichment)`);
    if (persistErrors) {
      console.log(`Persist errors:   ${persistErrors}`);
    }
  } else {
    console.log(`(dry-run — nothing persisted)`);
  }

  console.log("\nPer Source:");
  for (const source of stats.per_source) {
    console.log(
      `  ${source.source.padEnd(15)} found=${source.found} unique=${source.unique} errors=${source.errors} time=${source.elapsed_ms}ms`
    );
  }

  console.log("\nData Quality:");
  console.log(`  With GitHub URL:  ${stats.data_quality.with_github_url}`);
  console.log(`  With npm package: ${stats.data_quality.with_npm_package}`);
  console.log(`  With description: ${stats.data_quality.with_description}`);
  console.log(`  With category:    ${stats.data_quality.with_category}`);
}

main().catch((err) => {
  logger.error(err, "Crawl failed");
  process.exit(1);
});
