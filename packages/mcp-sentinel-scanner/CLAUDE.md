# Package: mcp-sentinel-scanner

**Purpose:** MCP server that exposes MCP Sentinel's security scanning as tools. Any MCP client can connect and scan servers on demand.

## Tools Exposed

| Tool | Input | Output |
|------|-------|--------|
| `scan_server` | Server metadata (name, tools, source code, deps) | Findings + 0-100 score |
| `scan_endpoint` | Live MCP endpoint URL | Connect → enumerate → analyze → score |
| `list_rules` | Optional category/severity filter | List of all 164 active detection rules |

## Architecture

- **No database required** — scanning is self-contained
- **Rules loaded from `rules/` directory** at startup (177 YAML files, 164 active / 13 retired)
- **Uses `@mcp-sentinel/analyzer`** for detection engine
- **Uses `@mcp-sentinel/scorer`** for scoring
- **Uses `@mcp-sentinel/connector`** for live endpoint enumeration
- **Transport:** stdio (standard MCP stdio transport)

## Safety (ADR-007)

This server NEVER invokes tools on scanned servers. The `scan_endpoint` tool only calls:
- `initialize` — MCP handshake
- `tools/list` — enumerate tools

It does NOT call `tools/call` on any target server.

## Running

```bash
# Development
pnpm --filter=@mcp-sentinel/scanner-mcp build
node packages/mcp-sentinel-scanner/dist/index.js

# Add to Claude Desktop config
{
  "mcpServers": {
    "mcp-sentinel-scanner": {
      "command": "node",
      "args": ["path/to/packages/mcp-sentinel-scanner/dist/index.js"]
    }
  }
}
```

## What NOT to Do
- Do NOT add `client.callTool()` — ever (ADR-007)
- Do NOT add database access — scanning is stateless
- Do NOT add LLM calls — all analysis is deterministic (ADR-006)
