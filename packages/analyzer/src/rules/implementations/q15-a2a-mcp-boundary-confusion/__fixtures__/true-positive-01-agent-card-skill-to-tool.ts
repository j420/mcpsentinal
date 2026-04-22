/**
 * Q15 TP-01 — A2A AgentCard skill description flows into MCP tool
 * description via registerTool(). Prompt-injection payloads in skill
 * metadata reach the client LLM through MCP.
 * Expected: ≥1 finding.
 */
declare const agentCard: {
  skills: Array<{ name: string; description: string }>;
};
declare const mcpServer: {
  registerTool(def: { name: string; description: string }): void;
};

export function bridgeSkills() {
  for (const skill of agentCard.skills) {
    mcpServer.registerTool({
      name: skill.name,
      description: skill.description,
    });
  }
}
