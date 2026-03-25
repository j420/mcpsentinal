# mcp-sentinel-scanner

MCP server that scans any MCP server against 177 security detection rules. Covers prompt injection, command injection, data exfiltration, supply chain attacks, OAuth vulnerabilities, and more.

## Tools

| Tool | Description |
|------|-------------|
| `scan_server` | Analyze server metadata (tools, source code, dependencies) — no live connection needed |
| `scan_endpoint` | Connect to a live MCP endpoint, enumerate tools, then analyze |
| `list_rules` | List all 177 detection rules, filterable by category/severity |

## Usage with Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "mcp-sentinel-scanner": {
      "command": "npx",
      "args": ["-y", "mcp-sentinel-scanner"]
    }
  }
}
```

## Example

Ask Claude: *"Scan the MCP server at https://example.com/mcp for security issues"*

The scanner will:
1. Connect to the endpoint (initialize + tools/list only — never invokes tools)
2. Run all 177 detection rules
3. Return findings with evidence + remediation + a 0-100 security score

## Detection Coverage

- **A1-A9**: Description analysis (prompt injection, unicode attacks, encoded instructions)
- **B1-B7**: Schema analysis (missing validation, dangerous defaults)
- **C1-C16**: Code analysis (command injection, SSRF, SQL injection, secrets)
- **D1-D7**: Dependency analysis (CVEs, typosquatting, malicious packages)
- **E1-E4**: Behavioral analysis (auth, transport, response time)
- **F1-F7**: Ecosystem context (lethal trifecta, exfiltration chains)
- **G1-G7**: Adversarial AI (indirect injection, rug pull, context saturation)
- **H1-H3**: 2026 attack surface (OAuth, initialize injection, multi-agent)
- **I1-I16**: Protocol surface (annotations, sampling, elicitation, consent fatigue)
- **J1-J7**: Threat intelligence (CVE-backed: git injection, schema poisoning)
- **K1-K20**: Compliance (NIST, ISO 27001, EU AI Act, OWASP Agentic Top 10)

## Safety

This scanner **never invokes tools** on target servers. It only calls `initialize` and `tools/list` for enumeration.

## License

MIT
