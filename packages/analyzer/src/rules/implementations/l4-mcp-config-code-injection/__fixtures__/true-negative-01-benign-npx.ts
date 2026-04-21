// L4 TN-01 — benign npx launcher with a stable package, safe env. Should not fire.

export const CONFIG = {
  mcpServers: {
    "file-reader": {
      command: "npx",
      args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp/shared"],
      env: {
        PORT: "3000",
        LOG_LEVEL: "info",
        NODE_ENV: "production",
      },
    },
  },
};
