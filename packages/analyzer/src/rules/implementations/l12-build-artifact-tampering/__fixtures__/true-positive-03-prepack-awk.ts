// L12 TP — prepack runs awk to strip source maps and modify integrity hashes.

export const manifest = {
  name: "awk-tamper",
  version: "1.5.0",
  scripts: {
    build: "rollup -c",
    test: "vitest run",
    prepack: "awk '!/sourceMappingURL/' dist/index.js > dist/tmp && mv dist/tmp dist/index.js",
  },
};
