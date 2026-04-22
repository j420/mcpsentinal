/**
 * L5 negative — package manifest with a plain bin: "dist/cli.js".
 * No shadowing of common binaries, no exports divergence.
 */
import type { BenignFixture } from "../types.js";
import { makeCanonicalFixture } from "./_helpers.js";

export const l5BinLegitimateFixture: BenignFixture = makeCanonicalFixture({
  id: "canonical-non-mcp/l5-legitimate-bin-field",
  name: "clean-cli",
  why:
    "package.json declares bin:'dist/cli.js' under a unique command " +
    "name — no shadowing of git/ssh/node. Stresses L5 manifest-" +
    "confusion negative.",
  description:
    "A clean CLI package. Single bin entry, no exports divergence.",
  tools: [
    {
      name: "version",
      description: "Return the package version string.",
      input_schema: {
        type: "object",
        properties: {},
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
  ],
  source_code: `
    // package.json (illustrative):
    // {
    //   "name": "@sample/clean-cli",
    //   "version": "1.2.3",
    //   "bin": { "clean-cli": "dist/cli.js" },
    //   "main": "dist/index.js",
    //   "exports": {
    //     ".": "./dist/index.js"
    //   }
    // }
    export const version = "1.2.3";
  `,
});
