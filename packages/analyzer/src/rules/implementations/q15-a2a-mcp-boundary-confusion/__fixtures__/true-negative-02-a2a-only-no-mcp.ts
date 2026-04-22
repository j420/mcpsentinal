/**
 * Q15 TN-02 — A2A surface is read but NEVER flows into an MCP sink.
 * A2A-only consumer with no cross-protocol bridge.
 * Expected: 0 findings.
 */
declare const agentCard: { skills: Array<{ name: string }> };

export function listSkills(): string[] {
  return agentCard.skills.map((s) => s.name);
}
