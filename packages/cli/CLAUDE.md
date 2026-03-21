# Package: cli

**Purpose:** `npx mcp-sentinel` — developer-facing tool for checking local MCP configs. The JSON output shape is a public API contract.

## Key Files
- `src/cli.ts` — main CLI logic, `check`, `discover`, `inspect`, `scan` commands
- `src/index.ts` — entry point

## Commands
```bash
npx mcp-sentinel check            # check local MCP config, human-readable output
npx mcp-sentinel check --json     # machine-readable JSON for CI integration
npx mcp-sentinel check --scan-all # scan ALL discovered configs across all tools
npx mcp-sentinel discover         # list all MCP configs found across all tools
npx mcp-sentinel discover --json  # JSON output of discovered configs
npx mcp-sentinel help             # usage info
```

## JSON Output Contract (treat as stable — breaking changes = major version bump)

```typescript
{
  "servers": [
    {
      "server_name": string,
      "score": number,           // 0–100
      "findings_count": number,
      "critical": number,
      "high": number,
      "medium": number,
      "low": number,
      "top_findings": string[]   // human-readable descriptions
    }
  ]
}
```

This JSON shape is consumed by CI pipelines and GitHub Actions. Changing field names or types is a breaking change.

## MCP Config File Auto-Discovery
The CLI discovers MCP configs from all major AI coding tools, cross-platform (macOS, Linux, Windows):

### Project-local configs (checked first)
1. `./claude_desktop_config.json`
2. `./mcp.json`
3. `./.mcp.json`
4. `.cursor/mcp.json` (Cursor)
5. `.vscode/mcp.json` (VS Code Copilot)
6. `.windsurf/mcp.json` (Windsurf)
7. `.kiro/mcp.json` (Kiro / AWS)

### Global configs (per-platform paths)
- **Claude Desktop**: `~/Library/Application Support/Claude/` (macOS), `~/.config/claude/` (Linux), `%APPDATA%/Claude/` (Windows)
- **Claude Code**: `~/.claude.json`
- **Cursor**: `<appData>/Cursor/User/globalStorage/cursor.mcp/mcp.json`
- **VS Code (Copilot)**: `<appData>/Code/User/globalStorage/github.copilot/mcp.json`
- **Windsurf (Codeium)**: `<appData>/Windsurf/User/globalStorage/codeium.windsurf/mcp.json`
- **Gemini CLI**: `~/.gemini/settings.json`
- **OpenClaw / ClawHub**: `~/.openclaw/config.json`

### Config shape normalization
The discovery logic normalizes different config shapes:
- `{ "mcpServers": { ... } }` — standard MCP config (most tools)
- `{ "servers": { ... } }` — alternate key used by some tools

### Key functions
- `discoverAllConfigs()` — returns ALL found configs with source attribution
- `getConfigCandidates()` — generates platform-specific candidate paths
- `normalizeConfig()` — normalizes different config shapes into MCPConfig

### Config source types
`ConfigSource`: `"claude-desktop"` | `"claude-code"` | `"cursor"` | `"vscode-copilot"` | `"windsurf"` | `"gemini-cli"` | `"kiro"` | `"openclaw"` | `"project-mcp"` | `"explicit"`

## What NOT to Do
- Do NOT change the JSON output schema without a major version bump
- Do NOT add commands that make network calls without explicit user opt-in
- Do NOT add interactive prompts — output must be scriptable
- Do NOT add DB access — the CLI is a standalone static analysis tool
