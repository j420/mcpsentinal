import { build } from "esbuild";
import { cpSync, mkdirSync, existsSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const rulesSource = join(__dirname, "..", "..", "rules");
const rulesDest = join(__dirname, "rules");

// Bundle the TypeScript source into a single JS file
await build({
  entryPoints: [join(__dirname, "src", "index.ts")],
  bundle: true,
  platform: "node",
  target: "node20",
  format: "esm",
  outfile: join(__dirname, "dist", "index.js"),
  // Externalize npm dependencies and native modules
  external: [
    "@modelcontextprotocol/sdk",
    "@modelcontextprotocol/sdk/*",
    "pino",
    "pino/*",
    "yaml",
    "zod",
    "tree-sitter",
    "tree-sitter-*",
  ],
  banner: {
    js: "#!/usr/bin/env node\n",
  },
  sourcemap: true,
  minify: false, // Keep readable for debugging
});

// Copy rules directory into the package for distribution
if (existsSync(rulesSource)) {
  if (existsSync(rulesDest)) {
    // Remove existing rules dir
    const { rmSync } = await import("fs");
    rmSync(rulesDest, { recursive: true, force: true });
  }
  mkdirSync(rulesDest, { recursive: true });
  cpSync(rulesSource, rulesDest, { recursive: true });
  console.log(`Copied ${rulesSource} → ${rulesDest}`);
} else {
  console.warn(`WARNING: Rules directory not found at ${rulesSource}`);
}

console.log("Bundle complete → dist/index.js + rules/");
