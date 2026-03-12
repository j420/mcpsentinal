import pino from "pino";
import { CrawlOrchestrator } from "./orchestrator.js";

const logger = pino({ name: "crawler:cli" });

async function main() {
  const sourceArg = process.argv[2];
  const sources = sourceArg ? [sourceArg] : undefined;

  const orchestrator = new CrawlOrchestrator(sources);
  const stats = await orchestrator.crawlAll();

  console.log("\n=== Crawl Summary ===");
  console.log(`Total discovered: ${stats.total_discovered}`);
  console.log(`New unique:       ${stats.new_unique}`);
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
