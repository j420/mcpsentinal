#!/usr/bin/env node
/**
 * Mutation audit CLI.
 *
 * Usage:
 *   pnpm --filter=@mcp-sentinel/red-team exec tsx src/mutation/cli.ts \
 *     --output=docs/mutations/latest.json
 *
 * Flags:
 *   --output=<path>    Write the JSON report (and sibling .md) here. Default:
 *                      docs/mutations/latest.json relative to repo root.
 *   --rule=<prefix>    Run only rules whose id starts with the prefix.
 *   --fixture=<substr> Only fixtures whose filename contains this substring.
 *
 * The CLI exits 0 on completion. It does NOT fail when a rule is blind to a
 * mutation — that's what the CHARTER parity guard is for. The runner emits a
 * structured report; consumers decide policy on top.
 */

import { existsSync } from "node:fs";
import { join, dirname, resolve, isAbsolute } from "node:path";
import { runMutationAudit } from "./runner.js";

function parseArgs(argv: string[]): { output: string; ruleFilter?: string; fixtureFilter?: string } {
  let output = "";
  let ruleFilter: string | undefined;
  let fixtureFilter: string | undefined;
  for (const arg of argv) {
    if (arg.startsWith("--output=")) output = arg.slice("--output=".length);
    else if (arg.startsWith("--rule=")) ruleFilter = arg.slice("--rule=".length);
    else if (arg.startsWith("--fixture=")) fixtureFilter = arg.slice("--fixture=".length);
    else if (arg === "--help" || arg === "-h") {
      console.log(
        [
          "pnpm exec tsx src/mutation/cli.ts [--output=<path>] [--rule=<prefix>] [--fixture=<substr>]",
          "",
          "Writes a JSON + Markdown mutation-audit report. No flag is required.",
          "Default output is <repo-root>/docs/mutations/latest.json.",
        ].join("\n"),
      );
      process.exit(0);
    }
  }
  const repoRoot = resolveRepoRoot();
  const finalOutput = output
    ? isAbsolute(output)
      ? output
      : resolve(repoRoot, output)
    : join(repoRoot, "docs", "mutations", "latest.json");
  return { output: finalOutput, ruleFilter, fixtureFilter };
}

/**
 * Find the repository root by walking up from this file until we hit a
 * directory that contains BOTH a `packages` folder and a `tsconfig.base.json`
 * — that combination is unique to the monorepo root.
 */
function resolveRepoRoot(): string {
  let dir = dirname(new URL(import.meta.url).pathname);
  for (let i = 0; i < 15; i++) {
    if (existsSync(join(dir, "packages")) && existsSync(join(dir, "tsconfig.base.json"))) {
      return dir;
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return process.cwd();
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const stderr = process.stderr;
  stderr.write(`[mutation-audit] running — output=${args.output}\n`);

  const report = runMutationAudit({
    ruleFilter: args.ruleFilter,
    fixtureFilter: args.fixtureFilter,
    writeReport: args.output,
    onEvent: (e) => {
      if (e.type === "mutation-error" || e.type === "fixture-error") {
        stderr.write(`[mutation-audit] ${e.type} rule=${e.rule_id} ${e.detail ?? ""}\n`);
      }
    },
  });

  stderr.write(
    `[mutation-audit] done — rules=${report.totals.rules_total} with_fixtures=${report.totals.rules_with_fixtures} survived_any=${report.totals.rules_survived_any} blind_all=${report.totals.rules_blind_all}\n`,
  );
}

main().catch((err) => {
  process.stderr.write(`[mutation-audit] fatal: ${err instanceof Error ? err.stack : String(err)}\n`);
  process.exit(1);
});
