# MCP Sentinel — Competitive Intelligence Report
## Last Updated: 2026-03-23

### Executive Summary

The MCP security market has **29+ active players** across 5 categories. Three waves of acquisitions (Snyk/Invariant, SentinelOne/Prompt Security, Check Point/Lakera) plus direct entry from platform giants (Cisco, Microsoft, Kong, Netskope, Proofpoint, Trend Micro) have transformed this from a niche to a hot enterprise category. Total AI security funding hit **$6.34B in 2025** (3x from 2024).

MCP Sentinel's unique position: **ecosystem-wide security intelligence registry** with 177 rules, 8 compliance frameworks, and historical trending. No competitor combines all three. The biggest risk is not technical — it's that we have **0 users looking at 0 data** while competitors ship "good enough" with 15 rules and get Gartner mentions.

---

### Market Categories

#### Category 1: Static Scanners (Direct Competitors)

| Tool | Org | Rules/Checks | Approach | Traction |
|------|-----|---|---|---|
| **snyk-agent-scan** | Snyk (acquired Invariant Labs, June 2025) | ~15+ risk types | Metadata + tool pinning (hash-based rug pull) + Toxic Flow Analysis | 1,700 GitHub stars, Snyk enterprise distribution |
| **Cisco MCP Scanner** | Cisco | YARA + LLM-as-judge + CFG builder + taint tracking | Behavioral code analysis v4.2, cross-file dataflow, supply chain subcommand | Enterprise backing |
| **Enkrypt AI MCP Scan** | Enkrypt AI | Agentic static analysis | Source code scanning + **public MCP Hub (1,000+ servers scored)** | Found 33% critical vulns |
| **MCPAmpel** | Independent | 16 independent security engines | Multi-engine aggregation | Free, no account |
| **NeuralTrust Scanner** | NeuralTrust | OWASP/MITRE/CWE mapped | Compliance-mapped scanning | Free scanner, paid platform |
| **MCPGuard** | Virtue AI | AI semantic analysis | LLM-powered code understanding | Found vulns in 78% of 700 servers |
| **MCP-Shield** | Independent | Tool poisoning + exfil + cross-origin | Optional Claude API for enhanced analysis | Open source, MIT |
| **MCPScan.ai** | Independent | LLM classifier | Tool description poisoning | Free web tool |
| **Proximity** | Thomas Roccia / Nova-Hunting | NOVA rule engine | Pattern-based + multiple LLM backends | Open source |
| **Knostic Scanner** | Knostic | Discovery-focused | Shodan filters, exposed server recon | Found 1,862 exposed servers |
| **MCP Sentinel** | Us | **177 rules, 17 categories (A-Q)** | Regex + schema + behavioral + composite, deterministic | **Not yet launched** |

#### Category 2: Runtime Gateways/Proxies

| Tool | Org | Key Feature | Status |
|------|-----|---|---|
| **Lasso MCP Gateway** | Lasso Security ($28M raised) | Plugin-based, PII masking, open source, Intent Deputy behavioral framework | Released, Gartner Cool Vendor |
| **PointGuard AI** | PointGuard | Zero-trust auth, 4D security framework | Announced March 2026 |
| **Operant AI** | Operant | Discovered "Shadow Escape" attack, Gartner featured in 5 reports | Released |
| **Microsoft MCP Gateway** | Microsoft | Kubernetes-native, open source | Released |
| **Gravitee MCP Proxy** | Gravitee | Protocol-level MCP understanding | Released |
| **Kong AI Gateway** | Kong | Session-aware, OAuth enforcement | Released |
| **Gopher Security** | Gopher | Post-quantum encryption, P2P architecture | Released |
| **Pangea** (CrowdStrike) | CrowdStrike (acquired Sept 2025) | MCP proxy, 99% prompt injection detection | Released |

#### Category 3: Enterprise Platforms

| Platform | Parent/Funding | MCP Coverage | Scale |
|----------|---|---|---|
| **Prompt Security** | SentinelOne (acquired Aug 2025) | Risk scoring across **13,000+ MCP servers** | Full Singularity integration |
| **Lakera** | Check Point (acquired 2026) | MCP boundary screening, zero-click RCE research | 80M adversarial patterns |
| **Straiker** | Independent (multi-$M deals) | MCP inventory + hygiene + live monitoring, discovered "MCP rebinding attack" | 8x growth in 6 months, Gartner named |
| **Pillar Security** | Independent | AI-SPM, MCP discovery + runtime guardrails | Gartner Representative Vendor |
| **Netskope** | Public (NTSK) | Network-level MCP traffic inspection + DLP | AWS AI Security Competency |
| **Proofpoint** | Independent | Secure Agent Gateway, DLP for MCP | Microsoft/OpenAI/Google partnerships |
| **TrendAI** | Trend Micro | NVIDIA OpenShell integration, dynamic behavioral analysis | Found 492 exposed servers |
| **ToolHive** | Stacklok ($17.5M) | Container-isolated MCP execution + verified registry + MCP Optimizer | "Most used open source MCP platform" |
| **Microsoft Agent 365** | Microsoft | Unified agent security control plane, Zero Trust for agents | GA May 2026 |
| **Okta for AI Agents** | Okta | Agents as first-class identities with auth + audit | GA April 2026 |

#### Category 4: Adjacent (Not MCP-Specific)

| Org | Product | MCP Coverage | Funding |
|-----|---------|---|---|
| **7AI** | Agentic security operations | None (SOC automation) | $130M Series A (largest cybersecurity A ever) |
| **Onyx Security** | AI control plane with supervisory agents | Indirect | $40M (March 2026) |
| **Oasis Security** | Non-human identity management | Agent identity | $120M Series B (March 2026) |
| **HiddenLayer** | AI threat detection, DoD SHIELD contract | Model-level | $56M |
| **Socket.dev** | Supply chain + MCP server for dependency checks | MCP server released | $65M |
| **Semgrep** | SAST with MCP server wrapper | MCP integration | Major OSS |
| **Palo Alto Prisma AIRS** | Runtime LLM protection | Tool misuse detection | Public company |
| **NeuralTrust** | Generative Application Firewall (GAF) | MCP gateway + scanner | Gartner recognized |

#### Category 5: Standards & Research

| Body | Output | Status |
|------|--------|--------|
| **OWASP** | MCP Top 10 (Phase 3, Feb 2026) + Practical Security Guide | Beta release |
| **OWASP** | Agentic Applications Top 10 (ASI01-10, Dec 2025) | Published, 100+ researchers |
| **CoSAI** | MCP Security whitepaper (12 threat categories, ~40 threats) | RSAC 2026 presentation |
| **MAESTRO** | 7-layer agentic AI threat model | Part of OWASP |
| **CSA AICM** | AI Controls Matrix (243 controls, 18 domains) | Won 2026 CSO Award |
| **NIST** | AI Agent Standards Initiative, RMF 1.1 addenda | Public comment through April 2026 |
| **EU AI Act** | General application begins **August 2, 2026** | Extraterritorial |
| **MCP Spec** | DPoP (SEP-1932), Workload Identity Federation (SEP-1933) | 2026 roadmap |
| **Trail of Bits** | mcp-context-protector, pajaMAS (multi-agent hijacking) | Active research |
| **CyberArk Labs** | Full Schema Poisoning (FSP), ATPA | Published |
| **Elastic Security Labs** | MCP attack vector research | Published |

---

### Key Acquisitions & Funding (2025-2026)

| Event | Date | Value | Significance |
|-------|------|-------|---|
| Google acquires Wiz | March 2026 | $32B | Cloud + AI security, Wiz has MCP server |
| OpenAI acquires Promptfoo | March 2026 | ~$86M val | LLM security testing |
| CrowdStrike acquires Pangea | Sept 2025 | Undisclosed | AI guardrails, MCP proxy |
| SentinelOne acquires Prompt Security | Aug 2025 | Undisclosed | GenAI security, 13K MCP servers scored |
| Snyk acquires Invariant Labs | June 2025 | Undisclosed | MCP-Scan creator, ETH Zurich pedigree |
| F5 acquires CalypsoAI | 2025-2026 | $180M | Inference-layer AI security |
| Check Point acquires Lakera | 2026 | Undisclosed | 80M adversarial patterns, Gandalf dataset |
| Cisco acquires Robust Intelligence | Oct 2024 | Undisclosed | AI firewall → Cisco AI Defense |
| ServiceNow acquires Moveworks + Veza | 2025 | Multi-billion | Agentic AI + identity security |
| 7AI Series A | Dec 2025 | $130M ($700M val) | Largest cybersecurity Series A in history |
| Oasis Security Series B | March 2026 | $120M ($195M total) | Agent identity management |
| Noma Security | 2025 | $100M | Agentic AI defense |
| Onyx Security | March 2026 | $40M | AI control plane |
| Lasso Security | 2025 | $28M total | MCP gateway + Intent Deputy |

---

### Market Statistics

- **$6.34B** total AI security funding in 2025 (3x from $2.16B in 2024)
- **48%** of cybersecurity pros rank agentic AI as top 2026 attack vector
- **40%** of enterprise apps will feature AI agents by 2026 (Gartner)
- **6%** of orgs have advanced AI security strategies (Gartner)
- **30+ CVEs** filed against MCP servers/clients in Jan-Feb 2026 alone
- **17,000+** MCP server listings across directories
- **1,862** exposed MCP servers with zero auth found by Knostic
- **492** exposed MCP servers with zero auth found by Trend Micro
- First confirmed malicious MCP server: **postmark-mcp** (BCC'd emails to attacker)
- PitchBook: AI-centric companies > 50% of global cybersecurity VC deals by late 2025
- LLM firewall market: ~$30M currently, projected 100% growth in 2026

---

### Academic Research

| Paper | Key Finding |
|-------|-------------|
| MCP-Guard (arXiv 2508.10991, Aug 2025) | 3-stage detection, **96.01% accuracy** — outperforms MCP-Scan (85.65%) and MCP-Shield (93.50%) |
| MCP at First Glance (arXiv 2506.13538, Jun 2025) | 1,899 servers: 7.2% general vulns, 5.5% tool poisoning, 66% code smells |
| Systematic Analysis / MCPLIB (arXiv 2508.12538, Aug 2025) | 31 attack methods in 4 classifications |
| MCP Landscape & Security (arXiv 2503.23278, Mar 2025) | 4-phase lifecycle threat taxonomy, 16 key activities |
| Enterprise MCP Security (arXiv 2504.08623, Apr 2025) | Enterprise mitigation frameworks |
| MCPGuard Agent Detection (arXiv 2510.23673, Oct 2025) | Agent-based vulnerability detection |
| Sampling Capability Abuse (arXiv 2601.17549) | 23-41% attack amplification via sampling |

---

### Feature Comparison Matrix

| Capability | MCP Sentinel | Snyk agent-scan | Cisco Scanner | Enkrypt AI | Prompt Security | MCPAmpel |
|---|---|---|---|---|---|---|
| Detection rule count | **177** | ~15 | YARA+LLM+CFG | AI-based | Unknown | 16 engines |
| Public ecosystem registry | **Planned** | No | No | **Yes (1K)** | **Yes (13K)** | On-demand |
| Source code SAST | **Yes (C1-C16)** | No | **Yes (CFG+taint)** | **Yes** | Unknown | Partial |
| Dependency analysis | **Yes (D1-D7)** | No | **Yes** | No | No | Partial |
| Unicode/homoglyph | **Yes (A6,A7)** | No | No | No | No | No |
| Cross-server analysis | **Yes (F7,I13,Q10)** | Partial (toxic flows) | No | No | No | No |
| Compliance mapping | **8 frameworks** | No | No | No | No | No |
| Historical trending | **Yes** | Tool pinning (hash) | No | No | No | No |
| Runtime proxy/gateway | No | Proxy mode | No | Gateway | Yes | No |
| Runtime monitoring | No | Guardrails | No | No | Yes | No |
| Dynamic testing | Gated (L5) | No | No | No | Yes | No |
| LLM-powered analysis | No (by design) | No | **Yes** | **Yes** | **Yes** | No |
| OWASP MCP Top 10 | **All 10** | Partial | Partial | Partial | Unknown | Partial |
| OWASP Agentic Top 10 | **ASI01-09** | No | No | No | No | No |
| MITRE ATLAS | **8 techniques** | No | No | No | No | No |
| Score/badge system | **Yes** | No | No | Rating | Risk scores | Trust score |
| CI/CD integration | **Yes** | **Yes** | **Yes** | **Yes** | **Yes** | No |
| Tool pinning (hash) | No (gap) | **Yes** | No | No | No | No |

---

### What MCP Sentinel Has That Nobody Else Does

1. **177 deterministic rules across 17 categories** — 3-10x more than any competitor
2. **8-framework compliance mapping** — ISO 42001, EU AI Act, NIST AI RMF, CoSAI, MAESTRO, CSA AICM, ISO 27001, OWASP (both MCP + Agentic)
3. **Dual OWASP mapping** — only tool mapping to both MCP Top 10 AND Agentic Top 10
4. **Historical score trending** — append-only scan history enables rug-pull detection and drift analysis
5. **No LLM dependency** — fully reproducible, auditable results (Cisco/Enkrypt/MCPGuard use LLM-as-judge)
6. **Unicode attack surface (A6, A7)** — zero competitors check homoglyphs or zero-width characters
7. **Circular data loop (F6)** — novel detection category, no equivalent in any tool
8. **Multi-step exfiltration chain (F7)** — cross-tool analysis not done by any other tool
9. **Protocol surface rules (I1-I16)** — annotation deception, sampling abuse, elicitation harvesting, consent fatigue
10. **Cross-agent propagation (H3)** — multi-agent attack chain detection

### What We're Missing (Ranked by Impact)

| Gap | Who Has It | Priority |
|-----|-----------|----------|
| **Live data (0 servers scanned)** | Prompt Security (13K), Enkrypt (1K) | **P0 — CRITICAL** |
| **Users (0 downloads)** | Snyk agent-scan (1,700 stars) | **P0 — CRITICAL** |
| **Deep static analysis (CFG, taint)** | Cisco Scanner v4.2 | **P1 — HIGH** |
| **Tool pinning (hash-based rug pull)** | Snyk agent-scan | **P1 — HIGH (easy win)** |
| **Config scanner UX** | Snyk agent-scan | **P1 — HIGH** |
| **Runtime gateway/proxy** | 7+ competitors | **P3 — Skip (different product)** |
| **LLM-powered analysis** | Cisco, Enkrypt, MCPGuard | **P3 — Skip (determinism is differentiator)** |
| **Enterprise identity** | Microsoft, Okta, Oasis | **P3 — Skip (not our market)** |
| **Runtime monitoring** | Akto, Operant, Lasso | **P3 — Skip (not our market)** |

---

### Three Real Threats

1. **Prompt Security / SentinelOne already scored 13,000 servers.** They have the registry data we don't, plus SentinelOne's enterprise distribution. If they publish a searchable public registry, our core differentiator erodes.

2. **Cisco's MCP Scanner has real static analysis.** CFG builder, taint tracking, reaching definitions, constant propagation, cross-file dataflow (v4.0+). Our 177 rules are broader but their analysis on the rules they DO have is deeper.

3. **Snyk agent-scan has the brand.** 1,700 GitHub stars, Snyk's enterprise distribution, ETH Zurich research pedigree. When developers think "MCP security" they think mcp-scan.

---

### Strategic Recommendations

#### Priority 1: SHIP (weeks, not months)
- Complete Layer 3 (SEO, structured data) — the registry is 90% built
- Run first live crawl + scan — get 10K+ servers with scores
- Get indexed by Google — own "mcp security score" search queries

#### Priority 2: Compete on CLI (days of work)
- Reposition `npx mcp-sentinel` as a config scanner (direct mcp-scan competitor)
- 177 rules vs 15 is the selling point — make it obvious in output

#### Priority 3: Easy Technical Wins
- Add tool pinning (hash-based manifest comparison) — half a day
- Add score change webhooks/alerts — nobody else does this
- Add Snyk-style "Toxic Flow Analysis" equivalent using our F7 chain detection

#### Priority 4: Close Cisco's Technical Gap (the 12 Tier-1 rules)
- Build temporal-drift.ts, cross-server-graph.ts, schema-translator.ts
- Extend taint-ast.ts with new sink categories
- This makes our analysis genuinely deeper than Cisco's on our coverage areas

#### Priority 5: Market Presence
- Publish "State of MCP Security" report with 10K+ server data
- Get listed on MCP security comparison articles
- Submit to OWASP MCP Top 10 as a reference tool

#### What NOT to Build
- Runtime gateway (7+ competitors, different product category)
- LLM-powered analysis (determinism is a feature, not a limitation)
- Enterprise identity/SSO (Microsoft and Okta have billions for this)
- Agent monitoring (Lasso, Operant, Palo Alto own this space)

---

### Exit Strategy Context

Every Tier 1 platform is acquiring MCP security tools. Acquisition criteria:
1. **Real data** — a database of 10K+ scored servers is a data asset
2. **Real users** — npm downloads, GitHub stars, enterprise pilots
3. **Unique capabilities** — 177 rules, compliance mapping, historical tracking

We have #3. We need #1 and #2. That means shipping.

The window is open but closing. The consolidation wave (8 acquisitions in 18 months) shows that platform giants buy rather than build — but they buy tools with traction, not tools with potential.
