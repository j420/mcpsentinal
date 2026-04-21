// L4 TN-02 — object literal that has a `command` field but no MCP config
// markers. Should not fire — L4 is scoped to MCP-shaped literals.

export const CLI_CONFIG = {
  commands: {
    start: { command: "bash", args: ["-c", "echo hello"] },
  },
};
