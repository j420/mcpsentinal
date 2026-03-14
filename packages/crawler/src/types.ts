import type { DiscoveredServer, SourceName } from "@mcp-sentinel/database";

export interface CrawlResult {
  source: SourceName;
  servers_found: number;
  new_unique: number;
  duplicates: number;
  errors: number;
  elapsed_ms: number;
  servers: DiscoveredServer[];
}

export interface CrawlerSource {
  name: SourceName;
  crawl(): Promise<CrawlResult>;
}

export interface CrawlStats {
  /** Total server occurrences across all sources (counts cross-source duplicates) */
  total_discovered: number;
  /** Unique servers in this crawl run (in-memory dedup — deduplicates within the run) */
  new_unique: number;
  per_source: Array<{
    source: string;
    found: number;
    /** Servers new to the in-memory seen-set at the time this source ran */
    unique: number;
    /** Servers already seen from a prior source in this same run */
    duplicates: number;
    errors: number;
    elapsed_ms: number;
  }>;
  data_quality: {
    with_github_url: number;
    with_npm_package: number;
    with_description: number;
    with_category: number;
  };
}

/** Extended stats returned by crawlAndPersist — includes DB-level dedup counts */
export interface CrawlPersistStats extends CrawlStats {
  /** Server records actually created in the DB (truly new) */
  new_to_db: number;
  /** Existing DB records enriched with new source data */
  enriched_existing: number;
  /** Total upsert calls that completed without error */
  persisted: number;
  /** Upsert calls that threw an error */
  persist_errors: number;
}
