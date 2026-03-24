# Package: benchmark

**Purpose:** Competitive benchmark framework that evaluates MCP Sentinel against competitor tools on a curated 100-server corpus with known ground truth. Measures precision, recall, unique detection rate, and false positive rate.

## Key Files
- `src/index.ts` — Benchmark runner CLI (no database required)
- `src/corpus.ts` — 100 curated MCP server scenarios in 4 categories
- `src/ground-truth.ts` — Manually verified findings, metrics computation
- `src/competitors.ts` — Competitor tool adapters (Snyk, Cisco, MCPAmpel, simulated baseline)
- `src/report.ts` — Markdown comparison report generator

## Corpus Categories (25 servers each)

| Category | Purpose | Ground Truth Source |
|----------|---------|-------------------|
| CVE-backed | Real CVEs from NVD | CVE advisory verification |
| Intentionally vulnerable | Adapted from red-team fixtures | Security engineer authored |
| Clean | Verified secure implementations | Manual code review |
| Tricky | Sanitized code that looks dangerous | AST-verified false positive traps |

## Target Metrics

| Metric | Target | Why |
|--------|--------|-----|
| Precision | >85% | Industry standard for SAST |
| Recall | >70% | Above average for static analysis |
| Unique detection rate | >30 findings | Vulnerabilities only we detect |
| False positive rate | <15% | Acceptable noise level |

## Running

```bash
pnpm benchmark                # Run benchmark, summary output
pnpm benchmark --report       # Generate Markdown report to results/
pnpm benchmark --json         # JSON output for CI
pnpm benchmark --competitors  # Include real competitor tools (if installed)
```

No database required — runs entirely on the in-memory corpus.

## Competitor Adapters

| Adapter | Tool | Availability |
|---------|------|--------------|
| `snyk-agent-scan` | Snyk Agent Scan (mcp-scan) | Requires npm install |
| `cisco-mcp-scanner` | Cisco MCP Scanner | Requires pip install |
| `mcpampel` | MCPAmpel | Public API (network required) |
| `baseline-regex` | Simulated 13-rule regex scanner | Always available (offline) |

When competitor tools are unavailable, the benchmark uses the simulated baseline for comparison. This gives a fair "typical MCP scanner" comparison without requiring tool installation.

## Adding Corpus Servers

1. Add a `BenchmarkServer` entry to the appropriate category array in `corpus.ts`
2. Include `expected_findings` (confirmed rule IDs) and `must_not_fire` (false positive traps)
3. Run `pnpm benchmark` to verify

## What NOT to Do
- Do NOT modify ground truth to make metrics look better — findings must be genuinely verified
- Do NOT cherry-pick corpus servers — maintain the 25/25/25/25 balance
- Do NOT add LLM evaluation — all benchmark scoring is deterministic
- Do NOT run competitor tools in CI without explicit opt-in (--competitors flag)
- Do NOT publish competitor results without verifying tool versions and availability
