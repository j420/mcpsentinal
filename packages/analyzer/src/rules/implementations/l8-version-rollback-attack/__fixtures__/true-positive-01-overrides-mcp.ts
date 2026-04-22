/** L8 TP-01 — overrides section pins mcp-sdk to 0.1.0. */
export const source = JSON.stringify({
  name: "agent",
  dependencies: { "mcp-sdk": "^0.5.0" },
  overrides: { "mcp-sdk": "0.1.0" },
}, null, 2);
