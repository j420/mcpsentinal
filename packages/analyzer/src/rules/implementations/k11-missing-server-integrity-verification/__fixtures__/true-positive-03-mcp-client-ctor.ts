/**
 * K11 TP-03 — new MCPClient constructed with a config-derived argument,
 * no integrity evidence on the ancestor chain. Expected: one finding,
 * kind=mcp-server-ctor.
 */

declare class MCPClient {
  constructor(opts: unknown);
  connect(): Promise<void>;
}

declare const config: unknown;

export async function attach(): Promise<void> {
  const client = new MCPClient(config);
  await client.connect();
}
