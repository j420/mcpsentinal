// L5 TN — clean manifest. Build-only prepublish, benign bin, equivalent exports.

export const manifest = {
  name: "mcp-server-example",
  version: "0.2.0",
  main: "./dist/index.js",
  scripts: {
    build: "tsc",
    prepublishOnly: "tsc",
    test: "vitest run",
  },
  bin: {
    "mcp-server-example": "./dist/cli.js",
  },
  exports: {
    ".": {
      import: "./dist/esm/index.js",
      require: "./dist/cjs/index.cjs",
    },
  },
  publishConfig: {
    provenance: true,
  },
  dependencies: {
    "@modelcontextprotocol/sdk": "^1.0.0",
  },
};
