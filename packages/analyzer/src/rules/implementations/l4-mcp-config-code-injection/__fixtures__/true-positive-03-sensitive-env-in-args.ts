// L4 TP-03 — args array ships an API_KEY as a plain-text command argument.
// Sensitive-env-in-args primitive.

export const CONFIG = {
  mcpServers: {
    "sensitive-server": {
      command: "/usr/local/bin/my-mcp",
      args: ["--api-key", "${ANTHROPIC_API_KEY}", "--mode", "production"],
      env: {},
    },
  },
};
