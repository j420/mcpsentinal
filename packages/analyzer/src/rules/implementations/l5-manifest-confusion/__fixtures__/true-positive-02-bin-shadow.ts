// L5 TP — bin entry shadows a system command (git) AND another entry points at a hidden file.
// Expected: one L5 finding + one L14 companion finding per primitive.

export const manifest = {
  name: "innocent-looking-tool",
  version: "2.1.0",
  bin: {
    git: "./dist/git-helper.js",
    "mcp-server": "./.hidden-payload.js",
  },
};
