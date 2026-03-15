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
 * SAFETY: This connector ONLY calls read-only enumeration methods:
 *   initialize, tools/list, resources/list, prompts/list
 * It NEVER invokes tools (tools/call). Dynamic tool invocation is a
 * separate, gated capability (see detection-rules.md Section F).
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

      // Capture declared capabilities for I12 (capability escalation) rule
      const serverCapabilities = client.getServerCapabilities();
      const declaredCapabilities = serverCapabilities ? {
        tools: !!serverCapabilities.tools,
        resources: !!serverCapabilities.resources,
        prompts: !!serverCapabilities.prompts,
        sampling: !!(serverCapabilities as Record<string, unknown>).sampling,
        logging: !!(serverCapabilities as Record<string, unknown>).logging,
      } : null;

      // Enumerate tools — ONLY tools/list, never invoke
      const toolsResult = await client.listTools();
      const responseTime = Date.now() - startTime;

      const tools = toolsResult.tools.map((tool) => ({
        name: tool.name,
        description: tool.description || null,
        input_schema: (tool.inputSchema as Record<string, unknown>) || null,
        annotations: (tool as Record<string, unknown>).annotations
          ? ((tool as Record<string, unknown>).annotations as Record<string, unknown>)
          : null,
      }));

      // Enumerate resources (Category I: I3, I4, I5 rules)
      let resources: Array<{ uri: string; name: string; description: string | null; mimeType: string | null }> = [];
      try {
        const resourcesResult = await client.listResources();
        resources = resourcesResult.resources.map((r: Record<string, unknown>) => ({
          uri: String(r.uri ?? ""),
          name: String(r.name ?? ""),
          description: (r.description as string) || null,
          mimeType: (r.mimeType as string) || null,
        }));
      } catch {
        // Server may not support resources — this is normal
      }

      // Enumerate prompts (Category I: I6 rule)
      let prompts: Array<{ name: string; description: string | null; arguments: Array<{ name: string; description: string | null; required: boolean }> }> = [];
      try {
        const promptsResult = await client.listPrompts();
        prompts = promptsResult.prompts.map((p: Record<string, unknown>) => ({
          name: String(p.name ?? ""),
          description: (p.description as string) || null,
          arguments: Array.isArray((p as Record<string, unknown>).arguments)
            ? ((p as Record<string, unknown>).arguments as Array<Record<string, unknown>>).map((a) => ({
                name: String(a.name ?? ""),
                description: (a.description as string) || null,
                required: Boolean(a.required),
              }))
            : [],
        }));
      } catch {
        // Server may not support prompts — this is normal
      }

      // Enumerate roots — not all servers support this capability
      let roots: Array<{ uri: string; name: string | null }> = [];
      try {
        const rootsResult = await (client as any).listRoots?.();
        if (rootsResult?.roots?.length) {
          roots = rootsResult.roots.map((r: any) => ({
            uri: String(r.uri ?? ""),
            name: r.name ?? null,
          }));
        }
      } catch {
        // Server may not support roots capability — this is normal
      }

      logger.info(
        {
          serverId,
          endpoint,
          tools: tools.length,
          resources: resources?.length ?? 0,
          prompts: prompts?.length ?? 0,
          roots: roots?.length ?? 0,
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
        resources,
        prompts,
        roots,
        declared_capabilities: declaredCapabilities,
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
        resources: [],
        prompts: [],
        roots: [],
        declared_capabilities: null,
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
