# Package: connector

**Purpose:** Connect to live MCP servers and enumerate their tools. This is the security boundary of the entire MCP Sentinel product.

## The One Rule That Cannot Be Broken

```
THIS PACKAGE ONLY CALLS:
  1. client.connect(transport)   → initialize handshake
  2. client.listTools()          → tools/list

NEVER:
  client.callTool()              → tools/call
  client.callTool()              → ANY tool invocation
```

This is enforced by `.claude/hooks/pre-tool-use/block-mcp-invocation.sh`.
It is also ADR-007 in `agent_docs/architecture.md`.
Violation: legal/ethical boundary, not a performance preference.

## Key Files
- `src/connector.ts` — `MCPConnector` class, the only class in this package
- `src/index.ts` — re-exports `MCPConnector` and `ConnectorOptions`

## Current API

```typescript
const connector = new MCPConnector({ timeout: 30000 });
const result: ToolEnumeration = await connector.enumerate(serverId, endpoint);
```

`ToolEnumeration` shape:
```typescript
{
  server_id: string
  tools: Array<{ name, description, input_schema }>
  connection_success: boolean
  connection_error: string | null
  response_time_ms: number
}
```

## Known Issue — P0 Bug (H2 Rule Blind)

**The `InitializeResult` from `client.connect()` is currently discarded.**

`client.connect(transport)` returns `InitializeResult` which contains:
- `serverInfo.name` — server's declared name
- `serverInfo.version` — server's declared version
- `result.instructions` — the H2 injection surface (spec field since `2024-11-05`)

These fields are needed by rule H2 (Initialize Response Injection) but are never captured.
The pipeline sets `initialize_metadata: undefined` as a result.

**Fix required:** Capture the `InitializeResult` and return it alongside `ToolEnumeration`.

```typescript
// Current (broken):
await Promise.race([connectPromise, timeoutPromise]);

// Should be:
const initResult = await Promise.race([connectPromise, timeoutPromise]);
// Then expose: initResult.serverInfo.name, initResult.serverInfo.version, initResult.instructions
```

See `packages/scanner/CLAUDE.md` for how the pipeline consumes this data.

## Transport Logic
- Endpoints ending in `/sse` or with `?sse=` → `SSEClientTransport`
- Everything else → `StreamableHTTPClientTransport` (spec `2025-03-26`)
- Both transports imported from `@modelcontextprotocol/sdk`

## What NOT to Do
- Do NOT add `client.callTool()` calls — ever
- Do NOT add retry logic for failed connections (the pipeline handles this)
- Do NOT change the timeout default without updating `ScanPipeline`
- Do NOT add business logic here — pure transport/enumeration only
