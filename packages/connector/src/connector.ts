import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { ToolEnumeration } from "@mcp-sentinel/database";
import pino from "pino";

const logger = pino({ name: "connector" });

const CONNECTION_TIMEOUT_MS = 30_000;

export interface ConnectorOptions {
  timeout?: number;
}

/**
 * MCP Connector — connects to MCP servers and enumerates tools.
 *
 * SAFETY: This connector ONLY calls `initialize` and `tools/list`.
 * It NEVER invokes tools. Dynamic tool invocation is a separate,
 * gated capability (see detection-rules.md Section F).
 */
export class MCPConnector {
  private timeout: number;

  constructor(options?: ConnectorOptions) {
    this.timeout = options?.timeout || CONNECTION_TIMEOUT_MS;
  }

  async enumerate(
    serverId: string,
    endpoint: string
  ): Promise<ToolEnumeration> {
    const startTime = Date.now();
    const client = new Client(
      { name: "mcp-sentinel-scanner", version: "0.1.0" },
      { capabilities: {} }
    );

    try {
      // Determine transport type
      const transport = this.createTransport(endpoint);

      // Connect with timeout
      const connectPromise = client.connect(transport);
      const timeoutPromise = new Promise<never>((_, reject) =>
        setTimeout(
          () => reject(new Error(`Connection timeout after ${this.timeout}ms`)),
          this.timeout
        )
      );

      await Promise.race([connectPromise, timeoutPromise]);

      // Capture initialize response fields for H2 rule analysis.
      // These are populated by the SDK during client.connect() and are accessible
      // immediately after the race resolves. They represent the three injection
      // surfaces in the MCP handshake: server name (in server record), version, instructions.
      const serverVersionInfo = client.getServerVersion();
      const serverInstructions = client.getInstructions();

      // Enumerate tools — ONLY tools/list, never invoke
      const toolsResult = await client.listTools();
      const responseTime = Date.now() - startTime;

      const tools = toolsResult.tools.map((tool) => ({
        name: tool.name,
        description: tool.description || null,
        input_schema: (tool.inputSchema as Record<string, unknown>) || null,
      }));

      logger.info(
        {
          serverId,
          endpoint,
          tools: tools.length,
          responseTime,
          server_version: serverVersionInfo?.version ?? null,
          has_instructions: !!serverInstructions,
        },
        "Tool enumeration complete"
      );

      return {
        server_id: serverId,
        tools,
        connection_success: true,
        connection_error: null,
        response_time_ms: responseTime,
        server_version: serverVersionInfo?.version ?? null,
        server_instructions: serverInstructions ?? null,
      };
    } catch (err) {
      const responseTime = Date.now() - startTime;
      const errorMsg = err instanceof Error ? err.message : String(err);

      logger.warn(
        { serverId, endpoint, error: errorMsg, responseTime },
        "Connection failed"
      );

      return {
        server_id: serverId,
        tools: [],
        connection_success: false,
        connection_error: errorMsg,
        response_time_ms: responseTime,
        server_version: null,
        server_instructions: null,
      };
    } finally {
      try {
        await client.close();
      } catch {
        // Ignore close errors
      }
    }
  }

  private createTransport(endpoint: string) {
    const url = new URL(endpoint);

    // Try Streamable HTTP first (newer protocol), fallback to SSE
    if (url.pathname.endsWith("/sse") || url.searchParams.has("sse")) {
      return new SSEClientTransport(url);
    }

    return new StreamableHTTPClientTransport(url);
  }
}
