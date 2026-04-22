// L12 TN — sed exists in prepublish but targets the source directory,
// NOT a build-output directory. Not an L12 primitive.

export const manifest = {
  name: "source-sed",
  version: "1.0.0",
  scripts: {
    build: "tsc",
    test: "vitest run",
    prepublishOnly: "sed -i s/dev/prod/ src/config.ts && tsc",
  },
};
