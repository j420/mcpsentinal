# MCP Sentinel — Crawler Specifications
## P5 Crawler Engineer Output — v1.0

### Source Priority Order

| Priority | Source | Expected Yield | API Type | Auth Required |
|----------|--------|---------------|----------|---------------|
| 1 | PulseMCP | High (1000+) | REST JSON | No |
| 2 | Smithery | High (2000+) | REST JSON | No |
| 3 | npm Registry | High (1500+) | REST JSON | No |
| 4 | GitHub Search | High (3000+) | REST JSON | Token recommended |
| 5 | PyPI | Medium (500+) | REST JSON | No |
| 6 | ZARQ/Nerq | High (17000) | REST JSON | No |
| 7 | Official MCP Registry | Medium | REST JSON | No |
| 8 | awesome-mcp-servers | Low (200) | GitHub Raw | No |
| 9 | Docker Hub | Low (100) | REST JSON | No |
| 10 | Glama | Medium | REST JSON | No |

### Crawl Frequency

- **Tier 1** (PulseMCP, Smithery, npm, GitHub): Daily
- **Tier 2** (PyPI, ZARQ, Official): Every 3 days
- **Tier 3** (awesome-list, Docker Hub, Glama): Weekly

### Deduplication Strategy

1. **Primary key:** Normalized GitHub URL (lowercase, no trailing slash, no .git)
2. **Secondary:** npm package name (exact match)
3. **Tertiary:** PyPI package name (exact match)
4. **Fallback:** Server name + author fuzzy match (>0.85 similarity)

### Rate Limiting

| Source | Rate Limit | Strategy |
|--------|-----------|----------|
| npm | ~250 req/min | 200ms delay |
| GitHub | 30 req/min (auth) | 2s delay + backoff |
| PyPI | ~100 req/min | 100ms delay |
| PulseMCP | Unknown | 500ms delay |
| Smithery | Unknown | 300ms delay |
