#!/usr/bin/env node
/**
 * accuracy-dashboard CLI.
 *
 * Usage:
 *   pnpm --filter=@mcp-sentinel/red-team accuracy-dashboard
 *   pnpm --filter=@mcp-sentinel/red-team accuracy-dashboard --fail-on-regression
 *   pnpm --filter=@mcp-sentinel/red-team accuracy-dashboard --targets <path>
 *   pnpm --filter=@mcp-sentinel/red-team accuracy-dashboard --latest <path> --trend <path>
 *
 * Writes:
 *   docs/accuracy/latest.json  (machine-readable snapshot)
 *   docs/accuracy/trend.md     (human-readable dashboard)
 *
 * Exit codes:
 *   0 — all rules at or above target, no regressions
 *   1 — when --fail-on-regression is set and either:
 *        * any rule measures below its declared target, OR
 *        * any rule regressed vs the prior snapshot
 *   2 — unrecoverable runtime error (missing targets file, invalid YAML, etc.)
 */
import { readdirSync, readFileSync, existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";
import { AccuracyRunner } from "../runner.js";
import { ALL_FIXTURES } from "../fixtures/index.js";
import {
  buildDashboard,
  writeDashboardArtefacts,
  readPriorSnapshot,
  DEFAULT_LATEST_PATH,
  DEFAULT_TREND_PATH,
} from "./dashboard.js";
import { loadAccuracyTargets } from "./target-loader.js";

const args = process.argv.slice(2);
const flag = (f: string) => args.includes(f);
const option = (f: string): string | undefined => {
  const i = args.indexOf(f);
  return i >= 0 ? args[i + 1] : undefined;
};

const failOnRegression = flag("--fail-on-regression");
const targetsPath = option("--targets");
const latestPath = option("--latest") ?? DEFAULT_LATEST_PATH;
const trendPath = option("--trend") ?? DEFAULT_TREND_PATH;
const rulesDir = option("--rules-dir") ?? resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../../../rules"
);
const prThresholdStr = option("--regression-threshold");
const regressionThreshold = prThresholdStr ? Number(prThresholdStr) : 0.05;

if (Number.isNaN(regressionThreshold) || regressionThreshold < 0 || regressionThreshold > 1) {
  console.error(`Invalid --regression-threshold: ${prThresholdStr}`);
  process.exit(2);
}

// ── Load rule metadata for richer dashboard output ────────────────────────

function loadRuleMetadata(): Map<string, { name: string; category: string; severity: string }> {
  const map = new Map<string, { name: string; category: string; severity: string }>();
  if (!existsSync(rulesDir)) return map;
  for (const f of readdirSync(rulesDir).filter(x => x.endsWith(".yaml") || x.endsWith(".yml"))) {
    try {
      const raw = parseYaml(readFileSync(resolve(rulesDir, f), "utf-8")) as
        | { id?: string; name?: string; category?: string; severity?: string; enabled?: boolean }
        | undefined;
      if (!raw || typeof raw !== "object" || !raw.id) continue;
      if (raw.enabled === false) continue;
      map.set(raw.id, {
        name: raw.name ?? raw.id,
        category: raw.category ?? "",
        severity: raw.severity ?? "",
      });
    } catch {
      // skip unparseable YAML — targets-loader handles missing targets.
    }
  }
  return map;
}

// ── Main ───────────────────────────────────────────────────────────────────

try {
  const targets = loadAccuracyTargets(targetsPath);
  const runner = new AccuracyRunner(rulesDir);
  const priorSnapshot = readPriorSnapshot(latestPath);
  const metadata = loadRuleMetadata();

  const { snapshot } = buildDashboard({
    runner,
    fixtures: ALL_FIXTURES,
    targets,
    priorSnapshot,
    regressionThreshold,
    ruleMetadata: metadata,
  });

  writeDashboardArtefacts({
    latestPath,
    trendPath,
    snapshot,
    priorSnapshot,
  });

  // ── Printed summary ─────────────────────────────────────────────────────
  const a = snapshot.aggregate;
  const pct = (v: number) => `${(v * 100).toFixed(1)}%`;

  console.log("─ MCP Sentinel — Accuracy Dashboard ──────────────────────────");
  console.log(`Generated:         ${snapshot.generated_at}`);
  console.log(`Rules audited:     ${a.rule_count}`);
  console.log(`Aggregate prec:    ${pct(a.precision)}`);
  console.log(`Aggregate recall:  ${pct(a.recall)}`);
  console.log(`Passing target:    ${a.passes_count} / ${a.rule_count}`);
  console.log(`Failing target:    ${a.fails_count}`);
  console.log(`Regressions:       ${a.regressions_count}`);
  console.log(`Prior snapshot:    ${priorSnapshot ? priorSnapshot.generated_at : "(baseline — none)"}`);
  console.log(`Artefacts written: ${latestPath}`);
  console.log(`                   ${trendPath}`);

  if (a.fails_count > 0 || a.regressions_count > 0) {
    console.log("");
    console.log(`${a.fails_count} rule(s) below target, ${a.regressions_count} regression(s) vs prior snapshot.`);
    // List them
    for (const r of snapshot.rules) {
      if (!r.passes || r.regressed) {
        const parts: string[] = [];
        if (!r.passes_precision)
          parts.push(`precision ${pct(r.measured_precision)} < target ${pct(r.target_precision)}`);
        if (!r.passes_recall && r.target_recall !== null)
          parts.push(`recall ${pct(r.measured_recall)} < target ${pct(r.target_recall)}`);
        if (r.regressed) parts.push(`regressed (Δprec ${(r.delta_precision * 100).toFixed(1)}pp, Δrec ${(r.delta_recall * 100).toFixed(1)}pp)`);
        console.log(`  ✗ ${r.rule_id}: ${parts.join("; ")}`);
      }
    }
  }

  // ── Gate ────────────────────────────────────────────────────────────────
  if (failOnRegression) {
    if (a.regressions_count > 0) {
      console.error(`::error::${a.regressions_count} rule(s) regressed vs prior snapshot`);
      process.exit(1);
    }
    if (a.fails_count > 0 && priorSnapshot) {
      // Only fail on below-target on subsequent runs. The baseline run
      // is allowed to record honesty-first below-target rules without
      // blocking the first commit of latest.json (noted in trend.md).
      console.error(`::error::${a.fails_count} rule(s) measured below target`);
      process.exit(1);
    }
  }

  process.exit(0);
} catch (err) {
  console.error("accuracy-dashboard failed:", err instanceof Error ? err.message : err);
  if (err instanceof Error && err.stack) console.error(err.stack);
  process.exit(2);
}
