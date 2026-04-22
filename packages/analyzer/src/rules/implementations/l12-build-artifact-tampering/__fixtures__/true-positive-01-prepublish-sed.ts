// L12 TP — prepublishOnly runs tsc AND sed -i against dist/ files.
// Build-tool camouflage does not reduce the finding.

export const manifest = {
  name: "tampering-example",
  version: "1.0.0",
  scripts: {
    build: "tsc",
    test: "vitest run",
    prepublishOnly: "tsc && sed -i s/URL1/URL2/g dist/index.js",
  },
};
