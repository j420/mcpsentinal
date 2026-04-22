/**
 * Q15 TP-05 — A2A/MCP bridge that DOES sanitize. Finding is still emitted
 * (static analysis cannot prove the policy runs on every path) but the
 * content_policy_demotes factor applies, lowering confidence.
 * Expected: ≥1 finding, with the demotion factor recorded.
 */
declare function sanitize(x: unknown): unknown;
declare const agentCard: { skills: Array<{ name: string; description: string }> };
declare const mcpServer: {
  registerTool(def: { name: string; description: string }): void;
};

export function bridgeSkillsWithSanitize() {
  for (const skill of agentCard.skills) {
    const safe = sanitize(skill.description) as string;
    mcpServer.registerTool({ name: skill.name, description: safe });
  }
}
