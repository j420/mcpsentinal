# Skill: Add Crawler Source

Use this skill whenever adding a new discovery source to the MCP Sentinel crawler.
Every crawler must emit exactly 6 required log fields or yield tracking breaks.

## When to Use
- User asks you to add a new crawler (e.g., MCP Server Cards, Glama, AgentAudit)
- A new registry or package source is discovered
- An existing SourceName enum entry has no crawler implementation

## Pre-Flight Checklist
1. Is the source already in the `SourceName` enum in `packages/database/src/schemas.ts`?
   - If YES: just implement the crawler
   - If NO: add it to the enum first
2. Does the source have a public API? Rate limits? Auth requirements?
3. What dedup key will servers from this source provide? (GitHub URL preferred)

## Step-by-Step

### Step 1: Add to SourceName enum (if not present)
File: `packages/database/src/schemas.ts`
```typescript
export const SourceName = z.enum([
  // ... existing sources ...
  "your-new-source",  // add here
]);
```

### Step 2: Create the crawler class
File: `packages/crawler/src/sources/<source-name>.ts`

Every crawler MUST implement `CrawlerSource` from `./types.ts`:
```typescript
import pino from "pino";
import type { CrawlerSource, CrawlResult } from "../types.js";
import type { DiscoveredServer } from "@mcp-sentinel/database";

const logger = pino({ name: "crawler:<source-name>" });

export class <SourceName>Crawler implements CrawlerSource {
  readonly name = "<source-name>";   // must match SourceName enum

  async crawl(): Promise<CrawlResult> {
    const start = Date.now();
    const servers: DiscoveredServer[] = [];
    let errors = 0;

    try {
      // --- fetch and transform servers here ---
    } catch (err) {
      errors++;
      logger.error({ err }, "Crawl failed");
    }

    // REQUIRED: log all 6 fields — yield tracking depends on this
    const elapsed_ms = Date.now() - start;
    logger.info(
      {
        source: this.name,            // field 1: source name
        servers_found: servers.length, // field 2: total found this run
        new_unique: 0,                // field 3: set by orchestrator after dedup
        duplicates: 0,                // field 4: set by orchestrator after dedup
        errors,                       // field 5: error count
        elapsed_ms,                   // field 6: wall-clock time
      },
      "Crawl complete"
    );

    return {
      source: this.name,
      servers_found: servers.length,
      new_unique: 0,     // orchestrator fills this in
      duplicates: 0,     // orchestrator fills this in
      errors,
      elapsed_ms,
      servers,
    };
  }
}
```

### Step 3: Map to DiscoveredServer shape
Each server you return must map to `DiscoveredServer`:
```typescript
{
  name: string,                    // required
  source_name: SourceName,         // required — use this.name
  source_url: string,              // required — URL of this server's listing
  external_id?: string,            // source's own ID for this server
  description?: string,
  github_url?: string,             // PRIORITY DEDUP KEY — normalize to lowercase, strip .git
  npm_package?: string,
  pypi_package?: string,
  author?: string,
  category?: ServerCategory,
  language?: string,
  license?: string,
  github_stars?: number,
  npm_downloads?: number,
  raw_metadata: Record<string, unknown>,  // store everything, judge later
}
```

**GitHub URL normalization** (critical for dedup):
```typescript
function normalizeGitHubUrl(url: string): string {
  return url.toLowerCase().replace(/\.git$/, "").replace(/\/$/, "");
}
```

### Step 4: Register in the orchestrator
File: `packages/crawler/src/orchestrator.ts`

Add import and add to `allSources` array in the correct position:
```typescript
import { YourNewCrawler } from "./sources/your-new-source.js";

// In constructor:
const allSources: CrawlerSource[] = [
  new McpRegistryCrawler(),          // official — run first
  new ModelcontextprotocolRepoCrawler(),
  new PulseMCPCrawler(),
  new SmitheryCrawler(),
  new YourNewCrawler(),              // add here in order of trust/quality
  new NpmCrawler(),
  new PyPICrawler(),
  new GitHubCrawler(),               // always last — widest net, most duplicates
];
```

### Step 5: Add pnpm script
File: `package.json` (root)
```json
"crawl:<source-name>": "pnpm --filter=crawler exec ts-node src/cli.ts --source=<source-name>"
```

### Step 6: Write a test
File: `packages/crawler/src/sources/<source-name>.test.ts`

Minimum: mock the HTTP call, verify the crawler returns the correct shape and logs required fields.

### Step 7: Run tests
```bash
pnpm test --filter=crawler
```

## Required Log Fields Reference
| Field | Type | Description |
|-------|------|-------------|
| `source` | string | Source name (matches SourceName enum) |
| `servers_found` | number | Total servers discovered this run |
| `new_unique` | number | Set by orchestrator post-dedup |
| `duplicates` | number | Set by orchestrator post-dedup |
| `errors` | number | Number of errors during crawl |
| `elapsed_ms` | number | Total wall-clock time in ms |

## Common Mistakes to Avoid
- **Not normalizing GitHub URLs**: dedup fails, duplicates flood the database
- **Missing raw_metadata**: always store the full source object — we collect everything, judge later
- **Not registering in orchestrator**: crawler class exists but never runs
- **Wrong source_name**: must exactly match the SourceName enum value
- **Pagination not handled**: many APIs default to 20-50 results — always follow `next` cursors
