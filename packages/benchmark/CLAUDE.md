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

## Architecture Decisions

### Engine Caching
The analyzer engine + 177 rules are loaded ONCE and reused for all 100 servers. This prevents 100x YAML parsing overhead.

### Vulnerability Class Mapping
Competitor tools use different rule ID namespaces (e.g., Sentinel uses "C1", baseline uses "CMD-INJ"). The `mapToVulnClass()` function normalizes both to a common vulnerability class (e.g., "command-injection") before computing unique-findings. Without this, every Sentinel finding would appear "unique" even when competitors detect the same vulnerability.

### Full FP Measurement
False positives are measured from TWO sources:
1. Explicit `must_not_fire` rules that incorrectly trigger
2. On clean/tricky servers, ANY finding not in `expected_findings` is counted as a false positive

This prevents gaming the benchmark by only listing a few `must_not_fire` rules.

### Zero-Division Handling
When TP=0 and FP=0, precision reports 0% (not 100%). A tool that finds nothing should not claim perfect precision.

## Corpus Design Rules

### Tricky servers MUST avoid regex-matchable patterns
If a tricky server's source code contains `exec(...)`, our regex rule C1 WILL match it. Putting C1 in `must_not_fire` creates a false expectation that regex can distinguish safe from unsafe `exec()` calls. Instead:
- Use variable names containing "exec" (e.g., `executor`, `execSummary`) to test word-boundary matching
- Use `execFile()` (different function) to test regex specificity
- Never put a regex-detectable call in tricky code and expect it not to fire

### Ground truth must match what the engine CAN detect
If cve-004 expects C5 (hardcoded secrets), the source code must contain an actual secret pattern that matches C5's regex — not just `process.env.VERSION`.

## Competitor Adapters

| Adapter | Tool | Status |
|---------|------|--------|
| `snyk-agent-scan` | Snyk Agent Scan (mcp-scan) | Placeholder — output parsing not yet implemented |
| `cisco-mcp-scanner` | Cisco MCP Scanner | Placeholder — output parsing not yet implemented |
| `mcpampel` | MCPAmpel | Placeholder — public API not yet available |
| `baseline-regex` | Simulated 13-rule regex scanner | Fully implemented, always available offline |

Competitor adapters that cannot parse real output report `available: false`. They are never included in metrics with empty findings (which would distort precision/recall).

## Adding Corpus Servers

1. Add a `BenchmarkServer` entry to the appropriate category array in `corpus.ts`
2. Include `expected_findings` (confirmed rule IDs) and `must_not_fire` (false positive traps)
3. For clean/tricky servers: verify source code does NOT contain regex patterns that match must_not_fire rules
4. Run `pnpm benchmark` to verify
5. Check unexpected findings output for new false positive sources

## What NOT to Do
- Do NOT modify ground truth to make metrics look better — findings must be genuinely verified
- Do NOT cherry-pick corpus servers — maintain the 25/25/25/25 balance
- Do NOT add LLM evaluation — all benchmark scoring is deterministic
- Do NOT run competitor tools in CI without explicit opt-in (--competitors flag)
- Do NOT publish competitor results without verifying tool versions and availability
- Do NOT put regex-matchable function calls in tricky servers and expect must_not_fire to pass
- Do NOT return `available: true` with empty findings from competitor adapters — this distorts metrics
