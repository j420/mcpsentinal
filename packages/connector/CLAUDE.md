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
  server_version: string | null        // from client.getServerVersion().version
  server_instructions: string | null   // from client.getInstructions()
}
```

`server_version` and `server_instructions` are `null` on failed connections.
`server_name` (serverInfo.name) is not captured here — it lives in the server DB record.
The analyzer combines all three for H2 rule analysis via the `server_initialize_fields` context.

## Initialize Response Fields (H2 Support)

After `client.connect(transport)` resolves, the SDK exposes the initialize handshake data:
- `client.getServerVersion()` → `{ name, version }` (serverInfo in the MCP spec)
- `client.getInstructions()` → `string | undefined` (the spec-sanctioned instructions field)

These are captured immediately after the connect race resolves and included in `ToolEnumeration`.
The pipeline passes them to `AnalysisContext.initialize_metadata` for H2 rule analysis.

## Transport Logic
- Endpoints ending in `/sse` or with `?sse=` → `SSEClientTransport`
- Everything else → `StreamableHTTPClientTransport` (spec `2025-03-26`)
- Both transports imported from `@modelcontextprotocol/sdk`

## What NOT to Do
- Do NOT add `client.callTool()` calls — ever
- Do NOT add retry logic for failed connections (the pipeline handles this)
- Do NOT change the timeout default without updating `ScanPipeline`
- Do NOT add business logic here — pure transport/enumeration only
