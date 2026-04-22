// L11 TN-01 — env block contains only safe-listed keys. Should not fire.

export const CONFIG = {
  mcpServers: {
    "safe-server": {
      command: "node",
      args: ["./server.js"],
      env: {
        PORT: "3000",
        HOST: "127.0.0.1",
        LOG_LEVEL: "info",
        NODE_ENV: "production",
        TZ: "UTC",
      },
    },
  },
};
