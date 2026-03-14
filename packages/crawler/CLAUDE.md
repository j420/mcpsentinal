# Package: crawler

**Purpose:** Discover MCP servers across multiple sources. Normalize them into `DiscoveredServer` shape. Deduplicate by canonical key.

## Key Files
- `src/orchestrator.ts` — `CrawlOrchestrator` — runs all sources, deduplicates
- `src/sources/` — one file per source
- `src/types.ts` — `CrawlerSource` interface, `CrawlResult`, `CrawlStats`
- `src/cli.ts` — `pnpm crawl` CLI entry point

## Active Sources (in execution order)

| Order | Class | Source Name | Why This Order |
|-------|-------|-------------|----------------|
| 1 | `McpRegistryCrawler` | `official-registry` | Highest trust, seeds canonical dedup keys |
| 2 | `ModelcontextprotocolRepoCrawler` | `github` | Official Anthropic repo |
| 3 | `PulseMCPCrawler` | `pulsemcp` | High quality community registry |
| 4 | `SmitheryCrawler` | `smithery` | Large registry, has endpoint metadata |
| 5 | `NpmCrawler` | `npm` | Package ecosystem |
| 6 | `PyPICrawler` | `pypi` | Package ecosystem |
| 7 | `GitHubCrawler` | `github` | Widest net, most duplicates — always last |

**Sources in SourceName enum with NO crawler yet:** `glama`, `docker-hub`, `awesome-mcp-servers`, `zarq`

## The 6 Required Log Fields

**Every crawler MUST log these 6 fields or yield tracking breaks:**

```typescript
logger.info({
  source: this.name,          // 1. source name
  servers_found: number,      // 2. total found
  new_unique: number,         // 3. set by orchestrator after dedup
  duplicates: number,         // 4. set by orchestrator after dedup
  errors: number,             // 5. error count
  elapsed_ms: number,         // 6. wall-clock ms
}, "Crawl complete");
```

Fields 3 and 4 are set by the orchestrator — your crawler returns 0 for both, the orchestrator fills them in.

## Deduplication Key Priority

The orchestrator deduplicates using this priority order:
```
1. github_url   → "gh:<normalized-url>"      (most reliable)
2. npm_package  → "npm:<package-name>"
3. pypi_package → "pypi:<package-name>"
4. fallback     → "name:<name>:<author>"     (least reliable — many collisions)
```

**Always normalize GitHub URLs:**
```typescript
url.toLowerCase().replace(/\.git$/, "").replace(/\/$/, "")
```

Failure to normalize creates duplicate database entries.

## Adding a New Source
Use `.claude/skills/add-crawler-source/SKILL.md` — it has the complete step-by-step.

## Running Crawlers
```bash
pnpm crawl                       # all sources
pnpm crawl:pulsemcp              # single source
pnpm crawl --source=npm,pypi     # multiple sources
```

## What NOT to Do
- Do NOT change the orchestrator source order without reason — official sources must seed dedup keys first
- Do NOT skip the 6 required log fields — yield analytics depend on them
- Do NOT add business logic in crawlers — normalize only, store everything in `raw_metadata`
- Do NOT filter servers based on quality — collect everything, judge later (ADR principle)
- Do NOT add inline SQL — crawlers call `db.upsertServer()` via the orchestrator
