import pino from "pino";
import pg from "pg";
import { CrawlOrchestrator } from "./orchestrator.js";
import { DatabaseQueries } from "@mcp-sentinel/database";
import type { CrawlStats, CrawlPersistStats, CrawlOptions } from "./types.js";

const logger = pino({ name: "crawler:cli" });

function parseIntArg(args: string[], flag: string): number | undefined {
  const arg = args.find((a) => a.startsWith(`${flag}=`));
  if (!arg) return undefined;
  const val = parseInt(arg.split("=")[1], 10);
  return Number.isNaN(val) ? undefined : val;
}

async function main() {
  const args = process.argv.slice(2);
  const dryRun = args.includes("--dry-run");
  const sourceArg = args.find((a) => !a.startsWith("--"));
  const sources = sourceArg ? [sourceArg] : undefined;
  const limit = parseIntArg(args, "--limit");

  const orchestrator = new CrawlOrchestrator(sources);
  const crawlOptions: CrawlOptions = { limit };

  if (limit) {
    logger.info({ limit }, "Crawl batch size limit set");
  }

  if (dryRun || !process.env.DATABASE_URL) {
    if (!process.env.DATABASE_URL) {
      logger.warn(
        "DATABASE_URL not set — running in dry-run mode (crawl only, no persistence)"
      );
    }
    const stats = await orchestrator.crawlAll(crawlOptions);
    printSummary(stats);
    return;

  }

  const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });

  // Handle idle connection resets from Railway proxy — without this handler,
  // ECONNRESET on an idle pooled connection crashes the entire process.
  pool.on("error", (err) => {
    logger.warn({ err: err.message }, "Idle pool connection error — pool will reconnect");
  });

  const db = new DatabaseQueries(pool);

  try {
    const stats = await orchestrator.crawlAndPersist(db, crawlOptions);
    printPersistSummary(stats);
  } finally {
    await pool.end();
  }
}

function printSummary(stats: CrawlStats) {
  console.log("\n=== Crawl Summary (dry-run) ===");
  console.log(`Total discovered: ${stats.total_discovered}`);
  console.log(`New unique:       ${stats.new_unique}`);
  console.log(`(dry-run — nothing persisted)`);
  _printPerSource(stats);
  _printDataQuality(stats);
}

function printPersistSummary(stats: CrawlPersistStats) {
  console.log("\n=== Crawl Summary ===");
  console.log(`Total discovered:  ${stats.total_discovered}`);
  console.log(`In-memory unique:  ${stats.new_unique}  (deduplicated within this run)`);
  console.log(`New to DB:         ${stats.new_to_db}  (truly new server records created)`);
  console.log(`Enriched existing: ${stats.enriched_existing}  (existing records updated with new source data)`);
  console.log(`Persisted calls:   ${stats.persisted}`);
  if (stats.persist_errors > 0) {
    console.log(`Persist errors:    ${stats.persist_errors}  ← check logs`);
  }
  _printPerSource(stats);
  _printDataQuality(stats);
}

function _printPerSource(stats: CrawlStats) {
  console.log("\nPer Source:");
  console.log(
    `  ${"source".padEnd(22)} ${"found".padStart(6)} ${"unique".padStart(7)} ${"dups".padStart(6)} ${"errors".padStart(7)} ${"time".padStart(8)}`
  );
  console.log(`  ${"-".repeat(60)}`);
  for (const s of stats.per_source) {
    console.log(
      `  ${s.source.padEnd(22)} ${String(s.found).padStart(6)} ${String(s.unique).padStart(7)} ${String(s.duplicates).padStart(6)} ${String(s.errors).padStart(7)} ${String(s.elapsed_ms + "ms").padStart(8)}`
    );
  }
}

function _printDataQuality(stats: CrawlStats) {
  const total = stats.total_discovered || 1; // avoid div-by-zero
  console.log("\nData Quality:");
  console.log(`  With GitHub URL:  ${stats.data_quality.with_github_url} (${pct(stats.data_quality.with_github_url, total)}%)`);
  console.log(`  With npm package: ${stats.data_quality.with_npm_package} (${pct(stats.data_quality.with_npm_package, total)}%)`);
  console.log(`  With description: ${stats.data_quality.with_description} (${pct(stats.data_quality.with_description, total)}%)`);
  console.log(`  With category:    ${stats.data_quality.with_category} (${pct(stats.data_quality.with_category, total)}%)`);
}

function pct(n: number, total: number): string {
  return Math.round((n / total) * 100).toString();
}

main().catch((err) => {
  logger.error(err, "Crawl failed");
  process.exit(1);
});
