# MCP Sentinel — Technical Roadmap: From Good to Fundable

_Created: 2026-03-23_
_Context: 20K+ servers crawled, 12K+ scanned, competitive landscape analyzed_

## Where We Are (Honest Assessment)

### What We Already Have (Better Than We Thought)

The engine is NOT "YAML grep." It's a **two-phase hybrid analyzer**:

**Phase 1 — 5 Specialized TypeScript Engines (Real Analysis):**
| Engine | Lines | What It Does | Covers |
|---|---|---|---|
| `CodeAnalyzer` | 22K | AST taint tracking via TS compiler API, interprocedural source→sink flows, sanitizer verification, entropy-based secret detection | C1–C16 |
| `DescriptionAnalyzer` | 16K | Linguistic injection scoring, Unicode homoglyph detection, encoding detection | A1–A9 |
| `SchemaAnalyzer` | 13K | Structural capability inference from JSON Schema, constraint density scoring, attack surface computation | B1–B7, E1–E4, F1–F7 |
| `DependencyAnalyzer` | 10K | CVE lookup (OSV API), Levenshtein typosquatting, malicious package DB, semver comparison | D1–D7 |
| `ProtocolAnalyzer` | 11K | Annotation deception, transport security, OAuth pattern detection, capability validation | H1–H3, I1–I2, I16 |

**Phase 2 — YAML Regex Fallback (for rules not covered by engines):**
- G1–G7 (Adversarial AI), I3–I15 (Protocol Surface), J1–J7 (Threat Intelligence)
- K1–K20 (Compliance), L–Q (Advanced categories)
- ~100 rules still on regex-only analysis

**Supporting Analyzers (real algorithms, not grep):**
| Analyzer | Lines | Algorithm |
|---|---|---|
| `taint-ast.ts` | 25K | 3-pass interprocedural taint: collect functions → walk AST → resolve sinks |
| `capability-graph.ts` | 25K | Directed graph with DFS cycle detection, BFS reachability, centrality scoring |
| `schema-inference.ts` | 22K | Semantic parameter classification (13 types), constraint density, risk scoring |
| `taint.ts` | 20K | Lexical fallback taint analysis (for when AST parsing fails) |
| `unicode.ts` | 15K | Homoglyph detection across 6 Unicode planes |
| `similarity.ts` | 15K | Multi-algorithm string distance for typosquatting |
| `entropy.ts` | 14K | Shannon entropy for secret detection |

### The 6 Real Gaps

| # | Gap | Impact | Why It Matters for Funding |
|---|---|---|---|
| **1** | **JS/TS only for AST taint** — Python MCP servers (FastMCP, ~40% of ecosystem) get regex fallback only | Critical | "We do AST analysis" is only half true — the fastest-growing part of the ecosystem gets weak coverage |
| **2** | **Single-file analysis** — no import resolution, no cross-module taint tracking | High | Real vulnerabilities span files: `utils.ts` sanitizer missing → `handler.ts` injection reachable |
| **3** | **50KB source cap** — large servers truncated | Medium | Some popular servers have 200KB+ of source. We're analyzing 25% of their code |
| **4** | **G–Q rules still on regex** — 94 rules (53% of total) use pattern matching, not structural analysis | High | Our marketing says 177 rules. But 94 of them are grep-quality, not AST-quality |
| **5** | **No cross-server graph** — each server analyzed in isolation | High | The lethal trifecta distributed across 3 servers in the same config is invisible |
| **6** | **No benchmark data** — we can't prove we find things competitors miss | Critical | For funding, "we have 177 rules" means nothing without evidence of superior detection |

---

## The Concrete Plan: 5 Moves to Get Funded

### Move 1: Python AST Analysis (Weeks 1–3)

**Why this is #1:** FastMCP is the dominant Python MCP framework. ~40% of MCP servers in the ecosystem are Python. Our taint analysis — the crown jewel — doesn't work on them.

**What to build:**
```
packages/analyzer/src/rules/analyzers/taint-python.ts
```

**Approach: tree-sitter-python via WASM**
- `tree-sitter` + `tree-sitter-python` npm packages give us full Python AST in TypeScript
- Same taint analysis architecture: sources → propagation → sinks → sanitizers
- Python-specific sources: `request.args`, `request.form`, `flask.request`, `os.environ`
- Python-specific sinks: `subprocess.run(shell=True)`, `os.system()`, `pickle.loads()`, `eval()`
- Python-specific sanitizers: `shlex.quote()`, `bleach.clean()`, parameterized queries

**Python sink registry (new):**
```typescript
const PYTHON_SINKS: SinkEntry[] = [
  { fn: "system", module: "os", dangerous_args: [0], category: "command_execution",
    sanitizers: ["shlex.quote"], why: "Direct shell execution", rule_id: "C1" },
  { fn: "run", module: "subprocess", dangerous_args: [0], category: "command_execution",
    sanitizers: ["shlex.split"], why: "subprocess with shell=True", rule_id: "C1" },
  { fn: "loads", module: "pickle", dangerous_args: [0], category: "deserialization",
    sanitizers: [], why: "Arbitrary code execution via pickle", rule_id: "C12" },
  { fn: "load", module: "yaml", dangerous_args: [0], category: "deserialization",
    sanitizers: ["safe_load", "SafeLoader"], why: "YAML deserialization RCE", rule_id: "C12" },
  { fn: "execute", module: "cursor", dangerous_args: [0], category: "sql_injection",
    sanitizers: ["parameterize", "%s"], why: "SQL without parameterization", rule_id: "C4" },
  { fn: "eval", module: null, dangerous_args: [0], category: "code_eval",
    sanitizers: [], why: "Arbitrary Python code execution", rule_id: "C16" },
];
```

**Integration:**
- `CodeAnalyzer.analyze()` detects language from file extension or content heuristics
- Routes to `analyzeASTTaint()` for JS/TS or `analyzePythonTaint()` for Python
- Same finding format, same confidence scoring, same evidence structure

**Deliverable:** Every Python MCP server gets the same quality taint analysis as JS/TS servers. Evidence shows `[AST taint — Python]` prefix to distinguish.

**Why this gets attention:** "The only MCP security tool that does real AST taint analysis on BOTH JavaScript and Python servers." Nobody else does this. AgentSeal uses LLM. BlueRock does regex. Snyk/Invariant only does runtime tracing.

---

### Move 2: Multi-File Import Resolution (Weeks 2–4)

**Why this matters:** The taint engine currently analyzes one concatenated blob. A `utils.ts` that exports a safe sanitizer is invisible to `handler.ts` analysis. This creates both false positives (flagging sanitized flows) and false negatives (missing flows through imported helpers).

**What to build:**
```
packages/scanner/src/import-resolver.ts
packages/analyzer/src/rules/analyzers/module-graph.ts
```

**Approach:**
1. **Import resolver** (in fetcher): When fetching source from GitHub, parse the main entry point's imports and fetch referenced files (up to 10 files, 200KB total cap)
2. **Module graph** (in analyzer): Build a map of exported symbols per file, then resolve cross-file references during taint analysis
3. **Cross-file taint propagation:** If `handler.ts` calls `getInput()` from `utils.ts`, and `getInput()` returns `req.body.cmd`, the taint flows across the module boundary

**Scope limits (to stay practical):**
- Max 10 files per server (follow direct imports only, not transitive)
- Max 200KB total source (up from 50KB)
- Only resolve relative imports (`./utils`, `../lib/db`) — not node_modules
- No dynamic imports (`require(variable)`)

**Evidence improvement:**
```
[AST taint — cross-module] http_body source "req.body.cmd" (handler.ts:L12) →
  import getInput from "./utils" → parameter binding → return value →
  command_execution sink "exec(cmd)" (handler.ts:L25).
  Module chain: utils.ts:getInput() → handler.ts:processRequest()
```

**Why this gets attention:** Cross-file taint analysis is what separates toy scanners from real SAST tools. CodeQL does it. Semgrep does it. No MCP-specific tool does it.

---

### Move 3: Competitive Benchmark (Weeks 3–5)

**Why this is critical for funding:** Investors don't fund "we have 177 rules." They fund "we found 3x more vulnerabilities than the competition, and here's the proof."

**What to build:**
```
packages/benchmark/
├── src/
│   ├── index.ts          # Benchmark runner
│   ├── corpus.ts         # Curated server corpus (100 servers)
│   ├── ground-truth.ts   # Manually verified findings
│   ├── competitors.ts    # Run competitor tools on same corpus
│   └── report.ts         # Generate comparison report
├── corpus/               # 100 curated servers with known vulnerabilities
└── results/              # Published benchmark results
```

**Approach:**
1. **Curate 100 MCP servers** with manually verified vulnerabilities:
   - 25 with known CVEs (ground truth from NVD)
   - 25 with intentionally vulnerable patterns (our red-team fixtures made into real servers)
   - 25 clean servers (verify no false positives)
   - 25 "tricky" servers (sanitized code, safe patterns that look dangerous)

2. **Run 4 tools on same corpus:**
   - MCP Sentinel (our tool)
   - AgentSeal (their public API/CLI)
   - BlueRock (their public scanner)
   - mcp-scan / Snyk Agent Scan (if accessible)

3. **Measure:**
   - **Precision:** What % of our findings are real vulnerabilities?
   - **Recall:** What % of known vulnerabilities do we find?
   - **Unique finds:** Vulnerabilities ONLY we detect (this is the money metric)
   - **False positive rate:** How noisy are we vs. competitors?

4. **Publish results** as "MCP Security Tool Benchmark Q1 2026"

**Target metrics for fundraising deck:**
- Precision > 85% (industry standard for SAST)
- Recall > 70% (above average for static analysis)
- Unique detection rate: > 30% of findings not caught by any competitor
- False positive rate: < 15%

**Why this gets attention:** Benchmarks are the currency of security tooling. Semgrep publishes benchmarks. Snyk publishes benchmarks. We should too.

---

### Move 4: Ecosystem Intelligence Report (Weeks 4–6)

**Why this matters:** We have scanned 12K+ servers. Nobody else has this dataset. This is our unique asset.

**What to build:**
```
packages/reports/
├── src/
│   ├── ecosystem-stats.ts     # Aggregate statistics from scan data
│   ├── trend-analysis.ts      # Score distribution, vulnerability prevalence
│   ├── category-breakdown.ts  # Findings by category, severity, framework
│   └── generator.ts           # Markdown/PDF report generator
└── output/
    └── state-of-mcp-security-q1-2026.md
```

**Report contents ("State of MCP Security Q1 2026"):**
1. **Ecosystem Overview:** 20K servers crawled, 12K scanned, language distribution, framework distribution
2. **Vulnerability Prevalence:**
   - % of servers with critical findings
   - Most common vulnerability categories
   - Severity distribution across ecosystem
3. **Framework Comparison:**
   - FastMCP vs. @modelcontextprotocol/sdk vs. custom implementations
   - Which framework produces more secure servers?
4. **OWASP MCP Top 10 Coverage:**
   - Which OWASP categories have the most violations?
   - Compliance rate across ecosystem
5. **Taint Analysis Deep Dives:**
   - Real (anonymized) taint flows found in popular servers
   - "Here's what AST analysis catches that regex misses" — side-by-side comparison
6. **Recommendations:**
   - For server authors: top 5 things to fix
   - For AI clients: what to check before connecting
   - For enterprises: minimum security requirements

**Distribution:**
- Publish on our website
- Submit to OWASP MCP project
- Pitch to security media (The Hacker News, Bleeping Computer, Dark Reading)
- Present at security conferences (DEF CON AI Village, BSides, OWASP AppSec)

**Why this gets attention:** Astrix published "State of MCP Server Security 2025" and got massive press. We have 12x their dataset and 8x their rule coverage. Our report should be definitive.

---

### Move 5: Lift G–Q Rules from Regex to Structural Analysis (Weeks 5–8)

**Why this matters:** 94 rules (53%) are still regex fallback. The highest-value ones should graduate to engine-quality analysis.

**Priority rules to upgrade (sorted by impact):**

| Rule | Current | Upgrade To | Why |
|---|---|---|---|
| **G1** (Indirect Injection Gateway) | Keyword match on tool names | Capability graph reachability: does a tool ingesting external content have a data path to a tool that acts on its output? | This is our most cited rule — it should be our strongest |
| **J1** (Cross-Agent Config Poisoning) | Regex for config paths | AST: detect `writeFileSync`/`fs.writeFile` calls where the path argument contains agent config paths AND the content is user-influenced | Real taint analysis on the #1 CVE-backed rule |
| **J5** (Tool Output Poisoning) | Regex for LLM manipulation strings in source | AST: trace error handler code paths — does the catch block construct a response containing user input + manipulation patterns? | Static detection of runtime attacks is our differentiator |
| **K5** (Auto-Approve Pattern) | Regex for `auto_approve` | AST: detect confirmation bypass patterns — `confirm()` mocked/overridden, `--yes` flags, `UNSAFE_` prefixes in function names | Compliance rules need structural analysis to be credible |
| **I7** (Sampling Abuse) | Capability presence check | Capability graph: server declares sampling + has tools that ingest external content → compute feedback loop risk score using graph centrality | Our I-category rules should use the graph we already built |

**How to do it:**
- Each rule upgrade is a new method in the appropriate engine (ProtocolAnalyzer, CodeAnalyzer, or SchemaAnalyzer)
- Engine Phase 1 catches the rule → YAML Phase 2 skips it (already implemented via `engineRuleIds` set)
- Test with existing red-team fixtures + new test cases

**Target:** Move the top 20 highest-severity G–Q rules from regex to engine analysis. That brings the engine-analyzed percentage from 47% to 58%.

---

## What This Gets Us

### Before (Today)
- "We have 177 rules" (but 94 are regex)
- "We do AST analysis" (but only on JS/TS)
- "We scanned 12K servers" (but no published results)
- "We're different from competitors" (but no proof)

### After (8 Weeks)
- "We do interprocedural AST taint analysis on JS/TS AND Python — the only MCP tool that does this"
- "We have published benchmarks showing 3x detection rate vs. competitors"
- "We published the definitive State of MCP Security report with 12K+ servers analyzed"
- "Our top 83 rules use real program analysis, not regex — and we can show you the taint flow evidence"

### For the Funding Deck
1. **Technical moat:** AST taint analysis in 2 languages + cross-file resolution. Nobody else has this.
2. **Data moat:** 12K+ scanned servers with historical baselines. Largest MCP security dataset.
3. **Credibility:** Published benchmark, ecosystem report, OWASP contribution.
4. **Timing:** EU AI Act enforcement Aug 2026. Enterprises need compliance evidence NOW.

---

## Implementation Schedule

| Week | Move | Deliverable |
|---|---|---|
| 1 | Python AST | tree-sitter integration, Python sink registry |
| 2 | Python AST + Import Resolution | Python taint working, import resolver prototype |
| 3 | Import Resolution + Benchmark Setup | Cross-file taint working, benchmark corpus curated |
| 4 | Benchmark + Report | Run benchmarks, start ecosystem report |
| 5 | Report + Rule Upgrades | Publish report, upgrade G1/J1 to engine analysis |
| 6 | Rule Upgrades | Upgrade J5/K5/I7 to engine analysis |
| 7 | Rule Upgrades + Polish | Remaining rule upgrades, benchmark published |
| 8 | Integration + Launch | Full pipeline tested, public announcement |

## Dependencies

| Need | Source | Blocking? |
|---|---|---|
| `tree-sitter` + `tree-sitter-python` npm packages | npm | No — well-maintained, WASM builds available |
| Competitor tool access | Public APIs/CLIs | Partial — AgentSeal has public API, others may need accounts |
| Ground truth CVE data | NVD + GitHub Advisory | No — public data |
| Design/writing for report | Internal | No — can automate most of it from scan data |

## Risk Mitigation

| Risk | Mitigation |
|---|---|
| tree-sitter Python binding quality | Fallback: use `@vercel/python-wasm` or spawn Python subprocess for AST |
| Competitors block our benchmark access | Publish methodology anyway — they can run it themselves |
| Report finds embarrassing results (most servers are fine) | Unlikely given Astrix/AgentSeal data (33-66% have findings). But even "the ecosystem is healthier than feared" is a story |
| Import resolution is too slow | Hard cap at 10 files, 200KB. Performance budget: 5s per server max |

---

## What NOT To Build (Tempting But Wrong)

| Temptation | Why Not |
|---|---|
| LLM-powered analysis | ADR-006 still holds. Deterministic = auditable = enterprise-ready. AgentSeal uses LLM and that's their weakness, not their strength |
| Full Semgrep/CodeQL integration | Too heavy. Our taint engine is purpose-built for MCP analysis patterns. General SAST tools have 10,000 rules for web apps — we need 177 rules for MCP servers |
| Runtime instrumentation | Layer 5 dynamic tester already exists with consent gating. Don't duplicate |
| Mobile/desktop app | Web + CLI is sufficient. Don't spread focus |
| Pricing/billing | Post-funding. Free tier drives adoption. Enterprise pricing after first 10 customers |
