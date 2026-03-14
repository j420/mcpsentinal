# Runbook: Running a Full Crawl

Use this runbook to run a full crawl of all MCP server sources and persist results to the database.

## Prerequisites

```bash
# Verify database is running
docker-compose up -d postgres

# Verify DB is migrated and accessible
pnpm db:migrate
psql $DATABASE_URL -c "SELECT COUNT(*) FROM servers;"
```

## Step 1: Run the Full Crawl

```bash
# Dry run first — see what would be crawled without writing
pnpm crawl --dry-run

# Full crawl — all 7 sources, persists to DB
pnpm crawl
```

Expected console output per source:
```
INFO  source=official-registry found=518  unique=312 duplicates=206 errors=0  elapsed_ms=4200
INFO  source=pulsemcp           found=2847 unique=891 duplicates=1956 errors=2  elapsed_ms=12300
INFO  source=npm                found=3200 unique=1240 duplicates=1960 errors=0  elapsed_ms=45000
...
INFO  Crawl run complete total=12500 unique=8900 quality={with_github_url:7100, ...}
```

If a source shows `errors > 10`: investigate before continuing (rate limit, API change, network issue).

## Step 2: Verify Dedup Quality

```sql
-- Check server count
SELECT COUNT(*) FROM servers;

-- Check source distribution
SELECT s.source_name, COUNT(*) as count
FROM sources s
GROUP BY s.source_name
ORDER BY count DESC;

-- Check dedup quality: % with GitHub URL
SELECT
  COUNT(*) as total,
  COUNT(github_url) as with_github,
  ROUND(COUNT(github_url)::numeric / COUNT(*) * 100, 1) as pct_with_github
FROM servers;

-- Look for suspicious duplicates (same name, different IDs)
SELECT name, author, COUNT(*) as dupes
FROM servers
GROUP BY name, author
HAVING COUNT(*) > 1
ORDER BY dupes DESC
LIMIT 20;
```

**Target:** >80% of servers with at least one identifier (GitHub URL, npm package, or PyPI package).

## Step 3: Spot-Check Data Quality

```bash
# Check a few random servers look sane
psql $DATABASE_URL -c "SELECT name, github_url, npm_package, category FROM servers ORDER BY RANDOM() LIMIT 10;"
```

Look for: servers with no identifiers, servers with garbled names, servers with wrong category.

## Step 4: Handle Source Failures

If a source fails entirely (returns 0 servers):

```bash
# Re-run just that source
pnpm crawl:pulsemcp
pnpm crawl --source=npm
```

Common causes:
- **Rate limiting**: Wait 30 minutes, retry. Add jitter to crawler if recurring.
- **API change**: Check source's changelog or status page.
- **Auth expired**: Check API keys in `.env.local`.

## Step 5: Trigger Scanning (Layer 2)

After a successful crawl, queue newly discovered servers for scanning:

```bash
# Scan new/unscanned servers (up to 100 at a time by default)
pnpm scan

# Scan everything in batch (for a full first run)
pnpm scan --limit=10000 --concurrency=10
```

Monitor scan progress:
```sql
SELECT status, COUNT(*) FROM scans GROUP BY status;
SELECT AVG(findings_count), MIN(total_score), MAX(total_score), AVG(total_score) FROM scores;
```

## Crawl Schedule (Target)

| Frequency | Sources |
|-----------|---------|
| Daily | Official MCP Registry, PulseMCP, npm |
| Weekly | GitHub search, PyPI, Smithery |
| On-demand | modelcontextprotocol-repo, awesome-mcp-servers |

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `servers_found=0` for a source | API outage or rate limit | Check source status page, retry in 30min |
| `duplicates >> unique` | Dedup key mismatch | Check GitHub URL normalization in crawler |
| Crawl hangs >10min on one source | Infinite pagination or network hang | Kill, add `--source=` flag to skip the hanging source |
| DB `upsertServer` errors | Schema mismatch after migration | Run `pnpm db:migrate` and retry |
