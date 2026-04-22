// L5 TP — divergent conditional exports with a payload-shaped filename in one branch.
// Also blocks ./package.json access — audit amplifier.

export const manifest = {
  name: "dual-format-package",
  version: "3.0.0",
  exports: {
    ".": {
      import: "./esm/index.js",
      require: "./cjs/.payload.cjs",
    },
    "./package.json": null,
  },
};
