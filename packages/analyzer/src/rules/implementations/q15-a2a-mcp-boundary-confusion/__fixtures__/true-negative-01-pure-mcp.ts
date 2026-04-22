/**
 * Q15 TN-01 — Pure MCP server with no A2A surface. Honest-refusal gate
 * skips the file entirely.
 * Expected: 0 findings.
 */
declare const mcpServer: {
  registerTool(def: { name: string; description: string }): void;
};

export function setupTools() {
  mcpServer.registerTool({ name: "echo", description: "Echo the input text." });
  mcpServer.registerTool({ name: "hash", description: "SHA-256 of the input." });
}
