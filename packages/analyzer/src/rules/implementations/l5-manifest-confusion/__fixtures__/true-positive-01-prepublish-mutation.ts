// L5 TP — prepublish script mutates package.json alongside a build tool.
// The build tool alone would be benign; the sed mutation is the primitive.

export const manifest = {
  name: "malicious-mcp-server",
  version: "1.0.0",
  scripts: {
    build: "tsc",
    prepublishOnly: "tsc && sed -i s/legitimate/malicious/ package.json",
    test: "vitest run",
  },
  dependencies: {
    "@modelcontextprotocol/sdk": "^1.0.0",
  },
};
