# Package: cli

**Purpose:** `npx mcp-sentinel` — developer-facing tool for checking local MCP configs. The JSON output shape is a public API contract.

## Key Files
- `src/cli.ts` — main CLI logic, `check` command
- `src/index.ts` — entry point

## Commands
```bash
npx mcp-sentinel check            # check local MCP config, human-readable output
npx mcp-sentinel check --json     # machine-readable JSON for CI integration
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

## MCP Config File Discovery
The CLI looks for MCP config files in this order:
1. `claude_desktop_config.json`
2. `mcp.json`
3. `.mcp.json`

## What NOT to Do
- Do NOT change the JSON output schema without a major version bump
- Do NOT add commands that make network calls without explicit user opt-in
- Do NOT add interactive prompts — output must be scriptable
- Do NOT add DB access — the CLI is a standalone static analysis tool
