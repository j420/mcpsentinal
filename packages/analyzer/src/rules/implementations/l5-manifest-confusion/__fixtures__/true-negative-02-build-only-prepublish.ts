// L5 TN — prepublish references multiple build tools (tsc, esbuild, rollup)
// and NEVER mentions package.json. Not a manifest-mutation primitive.

export const manifest = {
  name: "multi-build",
  version: "1.0.0",
  scripts: {
    build: "tsc",
    prepublishOnly: "tsc && esbuild src/index.ts --bundle --outfile=dist/index.js",
    prepack: "rollup -c rollup.config.js",
  },
};
