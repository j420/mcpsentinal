# MCP Sentinel — Product Milestones
## P12 Product Strategist Output — v1.0

### Active Layer: Layer 1 (Data Foundation)

### 6-Layer Registry Plan

| Layer | Name | Status | Dependencies |
|-------|------|--------|-------------|
| 1 | Data Foundation | **ACTIVE** | None |
| 2 | Security Intelligence | Pending | Layer 1 |
| 3 | Public Interface | Pending | Layer 2 |
| 4 | Developer Tools | Pending | Layer 3 |
| 5 | Advanced Detection | Pending | Layer 4 |
| 6 | Compliance & Enterprise | Pending | Layer 5 |

---

### Layer 1: Data Foundation (Current Sprint)

**Goal:** Crawl and store MCP servers from 5+ sources, deduplicated into a single database.

**Deliverables:**
- [x] Database schema (PostgreSQL with FTS)
- [x] Crawler for npm
- [x] Crawler for GitHub
- [x] Crawler for PyPI
- [x] Crawler for PulseMCP
- [x] Crawler for Smithery
- [ ] Deduplication pipeline (integrated with DB)
- [ ] Crawl orchestration with logging
- [ ] First full crawl: target 5,000+ unique servers

**Success Criteria:** 5,000 unique servers in the database with >80% having at least one identifier (GitHub URL or package name).

---

### Layer 2: Security Intelligence

**Goal:** Run detection rules against every server and produce scored results.

**Deliverables:**
- [x] 30 detection rules across 6 categories (A/B/C/D/E/F)
- [x] Analysis engine that interprets YAML rules
- [x] Scoring algorithm (100 - penalties)
- [x] MCP Connector for tool enumeration
- [ ] Source code fetcher (GitHub raw content)
- [ ] Dependency auditor (npm audit / pip-audit)
- [ ] Full scan pipeline: crawl → connect → analyze → score
- [ ] Scan all 5,000 servers

**Success Criteria:** 5,000 servers scanned, findings distribution matches expectations (most servers should have some findings).

---

### Layer 3: Public Interface

**Goal:** Searchable public registry website with server detail pages.

**Deliverables:**
- [x] REST API (Express, all CRUD endpoints)
- [x] Badge generator (SVG)
- [ ] Next.js website with search
- [ ] Server detail page (score, findings, tools, history)
- [ ] Category browse pages
- [ ] Ecosystem dashboard
- [ ] SEO optimization (meta tags, structured data)

**Success Criteria:** Publicly accessible at mcp-sentinel.com, indexed by Google.

---

### Layer 4: Developer Tools

**Goal:** CLI tool and CI/CD integration for developers to check their MCP configs.

**Deliverables:**
- [x] CLI tool (npx mcp-sentinel check)
- [x] JSON output for CI
- [ ] GitHub Action for PR checks
- [ ] Badge embed documentation
- [ ] npm publish workflow

**Success Criteria:** 500 npm downloads in first month.

---

### Layer 5: Advanced Detection

**Goal:** Dynamic tool invocation testing, cross-server analysis.

**Deliverables:**
- [ ] Gated dynamic testing capability
- [ ] Cross-server risk matrix
- [ ] Red team validation of rules
- [ ] Rule accuracy auditing

**Success Criteria:** Detection precision >80% across all rule categories.

---

### Layer 6: Compliance & Enterprise

**Goal:** Compliance mapping, enterprise features, "State of MCP Security" report.

**Deliverables:**
- [ ] OWASP MCP Top 10 mapping complete
- [ ] MITRE ATLAS mapping complete
- [ ] EU AI Act readiness assessment template
- [ ] "State of MCP Security" quarterly report
- [ ] Responsible disclosure policy
- [ ] Server author dispute mechanism

**Success Criteria:** Report published, cited by 3+ publications.

---

### This Week's Priorities
1. Complete Layer 1 crawl pipeline end-to-end
2. Begin Layer 2 scan pipeline implementation
3. Design web UI wireframes (Layer 3 prep)

### What NOT To Build Now
- User authentication
- Payment/billing
- LLM-powered analysis
- Performance optimization
- Mobile UI
