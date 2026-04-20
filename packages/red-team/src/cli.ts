#!/usr/bin/env node
/**
 * Red team accuracy audit CLI.
 *
 * Usage:
 *   pnpm red-team                          # text output to stdout
 *   pnpm red-team --json                   # JSON output to stdout
 *   pnpm red-team --json --output out.json # JSON written directly to file (CI-safe)
 *   pnpm red-team --html                   # HTML report
 *   pnpm red-team --rule A1                # run only fixtures for rule A1
 *   pnpm red-team --category C             # run only C-category rules
 *   pnpm red-team --fail-fast              # exit 1 on first failure
 */
import { writeFileSync } from "node:fs";
import { AccuracyRunner } from "./runner.js";
import { ALL_FIXTURES } from "./fixtures/index.js";
import { formatTextReport, formatJsonReport, formatHtmlReport, printSummary } from "./reporter.js";

const args = process.argv.slice(2);
const flag = (f: string) => args.includes(f);
const option = (f: string) => {
  const i = args.indexOf(f);
  return i >= 0 ? args[i + 1] : undefined;
};

const jsonMode = flag("--json");
const htmlMode = flag("--html");
const failFast = flag("--fail-fast");
const ruleFilter = option("--rule");
const catFilter = option("--category");
const rulesDir = option("--rules-dir");
const outputPath = option("--output");

let fixtures = ALL_FIXTURES;

if (ruleFilter) {
  fixtures = fixtures.filter((f) => f.rule_id === ruleFilter.toUpperCase());
  if (fixtures.length === 0) {
    console.error(`No fixtures found for rule: ${ruleFilter}`);
    process.exit(1);
  }
}

if (catFilter) {
  fixtures = fixtures.filter((f) =>
    f.rule_id.toUpperCase().startsWith(catFilter.toUpperCase())
  );
  if (fixtures.length === 0) {
    console.error(`No fixtures found for category: ${catFilter}`);
    process.exit(1);
  }
}

const runner = new AccuracyRunner(rulesDir);
const report = runner.runAll(fixtures);

if (failFast && report.total_failed > 0) {
  printSummary(report);
  process.exit(1);
}

const payload = jsonMode
  ? formatJsonReport(report)
  : htmlMode
    ? formatHtmlReport(report)
    : formatTextReport(report);

if (outputPath) {
  // Write directly to file — bypasses stdout entirely so nothing (pino, stray
  // console.log, module-eval 'undefined', etc.) can interleave bytes into the
  // report. printSummary still goes to stdout so CI gets a quick readout.
  writeFileSync(outputPath, payload);
  printSummary(report);
} else {
  console.log(payload);
}

process.exit(report.total_failed > 0 ? 1 : 0);
