# MCP Sentinel

**The security intelligence layer for the MCP ecosystem.**

MCP Sentinel scans every public MCP server, measures its security posture across 83 detection rules, and publishes the results as a searchable registry. We are not a gateway. We are the data layer that sits upstream of every deployment decision in the MCP ecosystem.

[![Registry](https://img.shields.io/badge/registry-mcp--sentinel.com-blue)](https://mcp-sentinel.com)
[![Rules](https://img.shields.io/badge/detection_rules-83-critical)](agent_docs/detection-rules.md)
[![Servers](https://img.shields.io/badge/servers_scanned-10K%2B-green)](https://mcp-sentinel.com)

---

## What We Detect

83 detection rules across 10 categories:

| Category | Rules | Examples |
|----------|-------|---------|
| **A** Description Analysis | 9 | Prompt injection, zero-width character attacks, encoded instructions |
| **B** Schema Analysis | 7 | Missing input validation, dangerous parameter defaults |
| **C** Code Analysis | 16 | Command injection, hardcoded secrets (20+ token formats), JWT confusion |
| **D** Dependency Analysis | 7 | Known CVEs, typosquatting, dependency confusion attacks |
| **E** Behavioral Analysis | 4 | No auth, insecure transport, response time anomalies |
| **F** Ecosystem Context | 7 | Lethal trifecta, multi-step exfiltration chains, circular data loops |
| **G** Adversarial AI | 7 | Indirect injection gateways, rug-pull detection, DNS exfiltration |
| **H** 2026 Attack Surface | 3 | OAuth 2.0 insecure impl, initialize response injection, multi-agent propagation |
| **I** Protocol Surface | 16 | Annotation deception, sampling abuse, resource injection, consent fatigue, cross-config trifecta |

## Quick Start

### Check your MCP config
```bash
npx mcp-sentinel check
npx mcp-sentinel check --json   # CI-friendly JSON output
```

### Add a security badge to your MCP server repo
```markdown
![MCP Security Score](https://api.mcp-sentinel.com/api/v1/servers/YOUR-SERVER-SLUG/badge.svg)
```

### Query the API
```bash
# Search servers
curl "https://api.mcp-sentinel.com/api/v1/servers?q=filesystem&min_score=70"

# Get a server's findings
curl "https://api.mcp-sentinel.com/api/v1/servers/my-mcp-server/findings"

# Ecosystem stats
curl "https://api.mcp-sentinel.com/api/v1/ecosystem/stats"
```

## Score Interpretation

| Score | Rating | Meaning |
|-------|--------|---------|
| 80–100 | Good | Minor issues or clean |
| 60–79 | Moderate | Several medium-severity findings |
| 40–59 | Poor | High-severity findings present |
| 0–39 | Critical | Critical findings or lethal trifecta |

---

## Architecture

```
Discovery → Connection → Analysis → Scoring → Publication
(crawler)   (connector)  (analyzer)  (scorer)   (api + web)
```

7 crawl sources → 10,000+ servers → 60-rule analysis engine → 0–100 score → public registry

Each stage is an independent package. The pipeline is fault-tolerant — a failed source fetch doesn't stop analysis of tool descriptions.

See [agent_docs/architecture.md](agent_docs/architecture.md) for the full data model and pipeline specification.

## Development

```bash
# Install
pnpm install

# Database
docker-compose up -d postgres
pnpm db:migrate
pnpm db:seed

# Crawl
pnpm crawl

# Scan
pnpm scan

# API
pnpm dev --filter=api

# Web registry
pnpm dev --filter=web

# Run tests
pnpm test
pnpm typecheck
```

## Project Structure

```
mcp-sentinel/
├── CLAUDE.md              ← Session memory and coding rules
├── agent_docs/            ← Architecture decisions, detection rules, milestones
├── .claude/
│   ├── settings.json      ← Claude Code configuration
│   ├── hooks/             ← Automated guardrails
│   └── skills/            ← Reusable AI workflows
├── packages/
│   ├── crawler/           ← 7 discovery sources
│   ├── connector/         ← MCP SDK: initialize + tools/list only
│   ├── analyzer/          ← 60-rule detection engine
│   ├── scorer/            ← 0–100 composite scoring
│   ├── database/          ← PostgreSQL schema + all queries
│   ├── api/               ← Public REST API
│   ├── web/               ← Next.js registry website
│   └── cli/               ← npx mcp-sentinel
├── rules/                 ← 60 YAML detection rules
└── docs/runbooks/         ← Operational guides
```

## Contributing

- Read [CLAUDE.md](CLAUDE.md) before making changes
- Use `.claude/skills/add-detection-rule/SKILL.md` when adding rules
- Use `.claude/skills/add-crawler-source/SKILL.md` when adding crawlers
- All detection rules require: `rule_id`, `evidence`, `remediation`, `test_cases` (2 TP + 2 TN)
- Never add LLM API calls — all analysis is deterministic
- Never invoke MCP server tools during scanning — `initialize` and `tools/list` only

## Security

MCP Sentinel is a read-only registry. We never invoke MCP server tools during scanning.
If you discover a security issue with MCP Sentinel itself, please open a GitHub issue.

---

Built by the MCP Sentinel team. Data is the product.
