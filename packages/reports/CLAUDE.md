# Package: reports

**Purpose:** Generate "State of MCP Security" ecosystem intelligence reports from scan data. Reads from PostgreSQL, outputs Markdown or JSON.

## Key Files
- `src/ecosystem-stats.ts` — Aggregate metrics (crawled/scanned counts, score distributions, language/framework breakdown)
- `src/trend-analysis.ts` — Vulnerability prevalence over time, severity distribution, top vulnerabilities
- `src/category-breakdown.ts` — Framework comparison, OWASP compliance rates, AST vs regex detection stats
- `src/generator.ts` — Markdown report renderer (assembles all data into structured report)
- `src/cli.ts` — CLI entry point (`pnpm generate`)

## Running

```bash
# Generate Markdown report to stdout
DATABASE_URL=postgresql://... pnpm generate

# Generate to file
DATABASE_URL=postgresql://... pnpm generate --output output/state-of-mcp-security-q1-2026.md

# Raw JSON data
DATABASE_URL=postgresql://... pnpm generate --json
```

## Report Sections

1. **Executive Summary** — headline stats, key findings
2. **Ecosystem Overview** — crawled/scanned counts, score distribution, language/category breakdown
3. **Vulnerability Prevalence** — severity distribution, prevalence rates, top 20 vulns
4. **Comparison with Published Research** — our data vs Equixly, Enkrypt, MCPGuard, arXiv
5. **Framework Security Comparison** — FastMCP vs @modelcontextprotocol/sdk vs custom
6. **OWASP MCP Top 10 Compliance** — compliance rate per OWASP category
7. **AST vs Regex Detection** — what taint analysis catches that pattern matching misses
8. **Finding Category Distribution** — breakdown by rule category (A–Q)
9. **Security by Language** — TypeScript vs Python vs other
10. **Recommendations** — for server authors, AI clients, enterprises
11. **Methodology** — data collection, analysis, scoring, limitations

## Data Dependencies

All data comes from PostgreSQL via direct queries (not via `DatabaseQueries` class).
This package has its own pool connection because it runs as a standalone CLI tool,
not as part of the scan pipeline.

Queries read from:
- `servers` — crawled/scanned counts, language, category, latest_score
- `scans` — completed scan records
- `findings` — finding details (rule_id, severity, evidence, owasp_category)
- `score_history` — weekly trend windows
- `sources` — multi-source confirmation counts

## What NOT to Do
- Do NOT modify any database tables — this is a read-only reporting tool
- Do NOT include server names or URLs in the report — all evidence is anonymized
- Do NOT add LLM-generated analysis — report text is deterministic templates
- Do NOT change the report structure without updating this doc
- Do NOT include raw evidence strings without running them through `anonymizeEvidence()`
