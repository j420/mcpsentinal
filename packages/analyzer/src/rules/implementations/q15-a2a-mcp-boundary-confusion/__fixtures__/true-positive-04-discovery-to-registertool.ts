/**
 * Q15 TP-04 — A2A discoverAgents() output fed into MCP registerTool()
 * without cryptographic verification. Fake-agent-advertisement
 * (arXiv 2602.19555) lands directly as a registered MCP tool.
 * Expected: ≥1 finding.
 */
declare function discoverAgents(uri: string): Promise<Array<{ name: string; description: string }>>;
declare const mcpServer: {
  registerTool(def: { name: string; description: string }): void;
};

export async function autoBridge() {
  const agents = await discoverAgents("a2a://registry.example.invalid");
  for (const agent of agents) {
    mcpServer.registerTool({ name: agent.name, description: agent.description });
  }
}
