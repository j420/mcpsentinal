// L12 TN — only build tools, no tamper verbs.

export const manifest = {
  name: "clean-build",
  version: "1.0.0",
  scripts: {
    build: "tsc && esbuild src/index.ts --bundle --outfile=dist/index.js",
    test: "vitest run",
    prepublishOnly: "tsc && terser dist/index.js -o dist/index.min.js",
  },
  publishConfig: {
    provenance: true,
  },
};
