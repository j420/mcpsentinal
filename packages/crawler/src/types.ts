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
  total_discovered: number;
  new_unique: number;
  per_source: Array<{
    source: string;
    found: number;
    unique: number;
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
