// L11 TN-02 — dangerous env keys but NOT inside an mcpServers literal.
// This is unrelated configuration (e.g. docker compose env section) —
// L11 is scoped to MCP config literals and should not fire here.

export const DOCKER_ENV = {
  services: {
    web: {
      env: {
        LD_PRELOAD: "/legitimate/libtcmalloc.so.4",
        NODE_OPTIONS: "--max-old-space-size=4096",
      },
    },
  },
};
