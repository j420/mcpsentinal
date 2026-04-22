/**
 * Stresses L5 Manifest Confusion. A package.json declares BOTH `bin`
 * and `exports` — but they reference the same compiled entry point.
 * L5 fires when `bin` and `exports` diverge (the CVE-backed confusion
 * shape); harmonised entries are legitimate dual-mode packages.
 */
import type { BenignFixture } from "../types.js";

const sourceCode = `/* File: package.json */
{
  "name": "edge-l5-harmonious",
  "version": "1.0.0",
  "type": "module",
  "bin": { "edge-l5": "./dist/cli.js" },
  "exports": {
    ".": "./dist/index.js",
    "./cli": "./dist/cli.js"
  },
  "files": ["dist"],
  "scripts": { "build": "tsc" }
}
`;

export const l5HarmoniousManifestFixture: BenignFixture = {
  id: "edge-of-spec/l5-harmonious-manifest",
  bucket: "edge-of-spec",
  why_benign:
    "L5 Manifest Confusion. `bin` and `exports` both reference the same " +
    "compiled files — harmonised, not confused.",
  context: {
    server: {
      id: "edge/l5-manifest",
      name: "dual-mode-pkg",
      description: "Package with both CLI and library entry points.",
      github_url: null,
    },
    tools: [],
    source_code: sourceCode,
    dependencies: [],
    connection_metadata: null,
  },
};
