# Package: scanner

**Purpose:** The full 7-stage scan pipeline. Orchestrates all other packages to produce security findings and scores for a single server.

## Pipeline Stages (in order — do not reorder)

```
Stage 0: createScan()           → open immutable scan record in DB
Stage 1: SourceFetcher          → download source code from GitHub
Stage 2: DependencyAuditor      → enrich deps via OSV API (CVE data)
Stage 3: discoverEndpoint()     → find live HTTP endpoint from source metadata
Stage 4: MCPConnector           → enumerate tools via initialize + tools/list only
Stage 5: AnalysisEngine         → run all 164 active detection rules → FindingInput[]
Stage 6: computeScore()         → composite 0–100 score
Stage 7: Persist                → insertFindings + insertScore + completeScan
```

**Stage isolation**: a failed stage does NOT abort downstream stages.
- Failed source fetch → analysis still runs on tool descriptions
- Failed connection → static analysis still runs on source code
- Each failure is logged with the correlation ID (first 8 chars of server_id)

## Key Files
- `src/pipeline.ts` — `ScanPipeline` class, the entire pipeline
- `src/fetcher.ts` — `SourceFetcher` (GitHub raw content download)
- `src/auditor.ts` — `DependencyAuditor` (OSV API integration)
- `src/cli.ts` — `pnpm scan` CLI entry point
- `src/types.ts` — `ScanOptions`, `ScanServerResult`, `ScanRunStats`

## Initialize Metadata (H2 Rule)

`initialize_metadata` is populated from `ToolEnumeration.server_version` and
`server_instructions` when the live connection succeeds. When no endpoint is found,
or the connection fails, `initialize_metadata` remains `undefined` and H2 falls back
to scanning only `context.server.name` (the name from the DB record).

The analyzer's `server_initialize_fields` context combines:
1. `context.server.name` — always present (from DB)
2. `context.initialize_metadata.server_version` — present when connection succeeded
3. `context.initialize_metadata.server_instructions` — present when server provides them

## Concurrency
Default: 5 parallel server scans (`DEFAULT_CONCURRENCY = 5`).
Controlled by a `Semaphore` class at the bottom of `pipeline.ts`.
Do not remove the semaphore — without it, 100 parallel OSV API calls will rate-limit.

## Scan Modes
```bash
pnpm scan                        # batch: unscanned servers, limit 100
pnpm scan --server=<id>          # single server by ID
pnpm scan --rescan               # re-scan stale servers (>7 days)
pnpm scan --dry-run              # report what would be scanned, no writes
pnpm scan --concurrency=10       # override concurrency
```

## Immutability Rule (ADR-008)
Every scan record is immutable once created.
- `createScan()` → INSERT, returns scanId
- `completeScan(scanId, count, error)` → UPDATE status only (completed/failed)
- `insertFindings()` → INSERT, never UPDATE
- `insertScore()` → INSERT, never UPDATE

**Never add UPDATE statements to findings or scores.** Score history is a first-class product feature.

## What NOT to Do
- Do NOT reorder pipeline stages
- Do NOT remove stage isolation (the `try/catch` around each stage)
- Do NOT add `tools/call` invocations — MCPConnector enforces this
- Do NOT add inline SQL — all DB calls go through `db: DatabaseQueries`
- Do NOT change `DEFAULT_CONCURRENCY` without load testing first
