/**
 * accuracy/dashboard.ts
 *
 * The per-rule precision/recall dashboard. Runs the `AccuracyRunner` against
 * all fixtures, joins measurements with per-rule targets from
 * `rules/accuracy-targets.yaml`, and emits two artefacts:
 *
 *   - docs/accuracy/latest.json  — machine-readable snapshot, append-keyable
 *   - docs/accuracy/trend.md     — human-readable dashboard + regression diff
 *
 * The CLI wraps this module with a `--fail-on-regression` flag that exits 1
 * when any rule's measured precision/recall falls below its target or
 * regresses vs the prior snapshot committed to git.
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { AccuracyRunner } from "../runner.js";
import { ALL_FIXTURES } from "../fixtures/index.js";
import type { RuleFixtureSet, RuleAccuracy, AccuracyReport } from "../types.js";
import {
  loadAccuracyTargets,
  getTargetFor,
  type AccuracyTargets,
} from "./target-loader.js";

const __dirname_dashboard = dirname(fileURLToPath(import.meta.url));
const DEFAULT_RULES_DIR = resolve(__dirname_dashboard, "../../../../rules");

// ── Types (shape persisted to docs/accuracy/latest.json) ────────────────────

/**
 * Per-rule dashboard row. `passes` combines target-check + fixture-pass:
 *   - measured_precision >= target_precision
 *   - (target_recall === null) OR measured_recall >= target_recall
 *   - no catastrophic fixture failures (failed === 0 is not required —
 *     individual fixture failures are logged, only the aggregate gates pass)
 *
 * `delta_precision` / `delta_recall` are relative to the PRIOR snapshot
 * (from the `latest.json` already committed to git). On the very first run
 * these are 0 and `baseline_delta` is true.
 */
export interface DashboardRuleRow {
  rule_id: string;
  rule_name: string;
  severity?: string;
  category?: string;
  measured_precision: number;
  measured_recall: number;
  target_precision: number;
  target_recall: number | null;
  passes: boolean;
  passes_precision: boolean;
  passes_recall: boolean;
  delta_precision: number;      // prior → now
  delta_recall: number;         // prior → now
  baseline_delta: boolean;      // true when no prior snapshot was available
  regressed: boolean;           // delta below -threshold (default 0.05)
  tp: number;                   // total true-positive fixtures
  fp: number;                   // true-negatives that fired (false alarms)
  tn: number;                   // true-negatives that stayed silent
  fn: number;                   // true-positives that stayed silent (misses)
  total_fixtures: number;
  rationale: string;
}

export interface DashboardAggregate {
  precision: number;
  recall: number;
  rule_count: number;
  passes_count: number;
  fails_count: number;
  regressions_count: number;
}

export interface DashboardSnapshot {
  generated_at: string;
  rules_version: string;
  prior_snapshot_at: string | null;
  regression_threshold: number;
  rules: DashboardRuleRow[];
  aggregate: DashboardAggregate;
  retiredRules: string[];
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/** 13 retired rules per agent_docs/detection-rules.md. */
const RETIRED_RULE_IDS = [
  "O1", "O2", "O3", "O7",
  "Q1", "Q2", "Q5", "Q8", "Q9", "Q11", "Q12", "Q14",
  "M3",
] as const;

/**
 * Read every `rules/*.yaml` file (rule YAMLs only, not sidecars like
 * `framework-registry.yaml` or `accuracy-targets.yaml`) and return the set
 * of rule IDs whose top-level `enabled:` field is exactly `false`.
 *
 * A rule can be disabled without being retired — I14 is the canonical case
 * (flipped to `enabled: false` in chunk 2.1-bugfix until the TypedRuleV2
 * implementation lands). The dashboard must skip these rules: they have
 * fixtures but no engine handler, so any TP/TN they produce is vacuous
 * (see the reviewer's note on the initial baseline reporting I14 at
 * 100%/100%).
 */
function loadDisabledRuleIds(rulesDir: string = DEFAULT_RULES_DIR): Set<string> {
  const disabled = new Set<string>();
  if (!existsSync(rulesDir)) return disabled;
  const files = readdirSync(rulesDir).filter(
    (f) =>
      f.endsWith(".yaml") &&
      !f.startsWith("framework-") &&
      f !== "accuracy-targets.yaml",
  );
  for (const f of files) {
    const raw = readFileSync(resolve(rulesDir, f), "utf-8");
    // Field-presence check — cheaper than a full YAML parse, and exactly
    // mirrors the semantics loadRules() uses in the analyzer.
    const idMatch = raw.match(/^id:\s*(\S+)/m);
    const enabledMatch = raw.match(/^enabled:\s*(true|false)\s*$/m);
    if (!idMatch || !enabledMatch) continue;
    if (enabledMatch[1] === "false") disabled.add(idMatch[1]);
  }
  return disabled;
}

/**
 * Compute TP/FP/TN/FN counts for a rule from its fixture set and the
 * AccuracyRunner's RuleAccuracy output. We re-derive the raw confusion-matrix
 * cells because the RuleAccuracy type only surfaces aggregate precision/recall.
 */
function confusionMatrix(set: RuleFixtureSet, result: RuleAccuracy): {
  tp: number;
  fp: number;
  tn: number;
  fn: number;
} {
  let tp = 0, fp = 0, tn = 0, fn = 0;
  // The runner maps each fixture to a FixtureResult. Count them from the
  // failed_fixtures set + the totals. Each result passed if (expect_finding ===
  // got_finding). We reconstruct counts from the fixture kinds + the
  // per-class pass counts surfaced by the runner.

  // Fixtures by kind
  const truePositives = set.fixtures.filter(f => f.kind === "true_positive" && f.expect_finding === true);
  const trueNegatives = set.fixtures.filter(f => f.kind === "true_negative" && f.expect_finding === false);

  // How many of each kind failed.
  const failedTP = result.failed_fixtures.filter(r => r.kind === "true_positive" && r.expect_finding === true).length;
  const failedTN = result.failed_fixtures.filter(r => r.kind === "true_negative" && r.expect_finding === false).length;

  tp = truePositives.length - failedTP;   // TP fixtures that correctly fired
  fn = failedTP;                           // TP fixtures that stayed silent
  tn = trueNegatives.length - failedTN;    // TN fixtures that correctly stayed silent
  fp = failedTN;                           // TN fixtures that falsely fired

  return { tp, fp, tn, fn };
}

// ── Dashboard construction ──────────────────────────────────────────────────

export interface BuildDashboardInput {
  runner?: AccuracyRunner;
  fixtures?: RuleFixtureSet[];
  targets?: AccuracyTargets;
  priorSnapshot?: DashboardSnapshot | null;
  regressionThreshold?: number; // default 0.05
  ruleMetadata?: Map<string, { name?: string; category?: string; severity?: string }>;
  /**
   * Override the set of disabled rule IDs. Defaults to reading
   * `rules/*.yaml` for `enabled: false`. Pass an empty set to include every
   * rule unconditionally (used by unit tests).
   */
  disabledRuleIds?: Set<string>;
}

export interface BuildDashboardResult {
  snapshot: DashboardSnapshot;
  report: AccuracyReport;
}

/**
 * Build the dashboard snapshot from a live AccuracyRunner execution.
 * Pure function: takes inputs, returns snapshot + original AccuracyReport.
 */
export function buildDashboard(input: BuildDashboardInput = {}): BuildDashboardResult {
  const runner = input.runner ?? new AccuracyRunner();
  const fixtures = input.fixtures ?? ALL_FIXTURES;
  const targets = input.targets ?? loadAccuracyTargets();
  const prior = input.priorSnapshot ?? null;
  const regressionThreshold = input.regressionThreshold ?? 0.05;
  const meta = input.ruleMetadata ?? new Map();
  const disabledRuleIds = input.disabledRuleIds ?? loadDisabledRuleIds();

  const report = runner.runAll(fixtures);

  // Index prior rows by rule_id so we can compute deltas.
  const priorMap = new Map<string, DashboardRuleRow>();
  if (prior) {
    for (const row of prior.rules) priorMap.set(row.rule_id, row);
  }

  // Index fixture sets for confusion-matrix reconstruction.
  const fixtureSetById = new Map<string, RuleFixtureSet>();
  for (const fs of fixtures) fixtureSetById.set(fs.rule_id, fs);

  const dashboardRows: DashboardRuleRow[] = [];
  for (const acc of report.by_rule) {
    // Skip retired rules entirely from the dashboard.
    if ((RETIRED_RULE_IDS as readonly string[]).includes(acc.rule_id)) continue;
    // Skip rules whose YAML is `enabled: false` — their fixtures produce
    // vacuous precision/recall (no registered handler fires), and including
    // them inflates rule_count and the passing-rate headline numbers.
    if (disabledRuleIds.has(acc.rule_id)) continue;

    const t = getTargetFor(acc.rule_id, targets);
    const set = fixtureSetById.get(acc.rule_id);
    const cm = set
      ? confusionMatrix(set, acc)
      : { tp: 0, fp: 0, tn: 0, fn: 0 };

    const passesPrecision = acc.true_negative_precision >= t.target_precision;
    const passesRecall = t.target_recall === null
      ? true
      : acc.true_positive_recall >= t.target_recall;
    const passes = passesPrecision && passesRecall;

    const priorRow = priorMap.get(acc.rule_id);
    const baselineDelta = !priorRow;
    const deltaPrec = priorRow ? acc.true_negative_precision - priorRow.measured_precision : 0;
    const deltaRec = priorRow ? acc.true_positive_recall - priorRow.measured_recall : 0;

    // Regression: a measured value dropped by more than the threshold.
    const regressed = !baselineDelta && (
      deltaPrec < -regressionThreshold ||
      (t.target_recall !== null && deltaRec < -regressionThreshold)
    );

    const m = meta.get(acc.rule_id) ?? {};
    dashboardRows.push({
      rule_id: acc.rule_id,
      rule_name: acc.rule_name,
      severity: m.severity,
      category: m.category,
      measured_precision: round(acc.true_negative_precision),
      measured_recall: round(acc.true_positive_recall),
      target_precision: t.target_precision,
      target_recall: t.target_recall,
      passes,
      passes_precision: passesPrecision,
      passes_recall: passesRecall,
      delta_precision: round(deltaPrec),
      delta_recall: round(deltaRec),
      baseline_delta: baselineDelta,
      regressed,
      tp: cm.tp,
      fp: cm.fp,
      tn: cm.tn,
      fn: cm.fn,
      total_fixtures: acc.total,
      rationale: t.rationale,
    });
  }

  dashboardRows.sort((a, b) => a.rule_id.localeCompare(b.rule_id));

  const aggregate: DashboardAggregate = {
    precision: round(
      dashboardRows.reduce((s, r) => s + r.measured_precision, 0) / (dashboardRows.length || 1)
    ),
    recall: round(
      dashboardRows.reduce((s, r) => s + r.measured_recall, 0) / (dashboardRows.length || 1)
    ),
    rule_count: dashboardRows.length,
    passes_count: dashboardRows.filter(r => r.passes).length,
    fails_count: dashboardRows.filter(r => !r.passes).length,
    regressions_count: dashboardRows.filter(r => r.regressed).length,
  };

  const snapshot: DashboardSnapshot = {
    generated_at: report.generated_at,
    rules_version: report.rules_version,
    prior_snapshot_at: prior?.generated_at ?? null,
    regression_threshold: regressionThreshold,
    rules: dashboardRows,
    aggregate,
    retiredRules: [...RETIRED_RULE_IDS],
  };

  return { snapshot, report };
}

// ── Rendering ───────────────────────────────────────────────────────────────

export function renderLatestJson(snapshot: DashboardSnapshot): string {
  return JSON.stringify(snapshot, null, 2);
}

/**
 * Render the trend markdown: aggregate summary → category table → per-rule
 * table (worst regressions first, highlighting failures) → regression diff
 * section (empty on the baseline run).
 */
export function renderTrendMarkdown(snapshot: DashboardSnapshot, priorSnapshot: DashboardSnapshot | null): string {
  const lines: string[] = [];

  lines.push("# MCP Sentinel — Rule Accuracy Dashboard");
  lines.push("");
  lines.push(`_Generated: ${snapshot.generated_at}_`);
  lines.push(`_Rules version: \`${snapshot.rules_version}\`_`);
  if (priorSnapshot) {
    lines.push(`_Prior snapshot: ${priorSnapshot.generated_at}_`);
  } else {
    lines.push(`_Baseline run — no prior snapshot to compare against._`);
  }
  lines.push("");

  // Aggregate summary
  const a = snapshot.aggregate;
  const overallStatus = a.fails_count === 0 && a.regressions_count === 0 ? "PASS" : "FAIL";
  lines.push("## Summary");
  lines.push("");
  lines.push("| Metric | Value |");
  lines.push("|---|---|");
  lines.push(`| Rules audited | ${a.rule_count} |`);
  lines.push(`| Aggregate precision | ${pct(a.precision)} |`);
  lines.push(`| Aggregate recall | ${pct(a.recall)} |`);
  lines.push(`| Passing target | ${a.passes_count} / ${a.rule_count} |`);
  lines.push(`| Failing target | ${a.fails_count} |`);
  lines.push(`| Regressions vs prior | ${a.regressions_count} |`);
  lines.push(`| Regression gate | **${overallStatus}** |`);
  lines.push("");

  // Per-category table
  const byCat = new Map<string, DashboardRuleRow[]>();
  for (const r of snapshot.rules) {
    const cat = r.category ?? r.rule_id[0];
    if (!byCat.has(cat)) byCat.set(cat, []);
    byCat.get(cat)!.push(r);
  }
  lines.push("## By Category");
  lines.push("");
  lines.push("| Category | Rules | Avg Precision | Avg Recall | Passes / Total |");
  lines.push("|---|---|---|---|---|");
  const cats = [...byCat.entries()].sort(([a], [b]) => a.localeCompare(b));
  for (const [cat, rows] of cats) {
    const avgP = rows.reduce((s, r) => s + r.measured_precision, 0) / rows.length;
    const avgR = rows.reduce((s, r) => s + r.measured_recall, 0) / rows.length;
    const passes = rows.filter(r => r.passes).length;
    lines.push(`| ${cat} | ${rows.length} | ${pct(avgP)} | ${pct(avgR)} | ${passes} / ${rows.length} |`);
  }
  lines.push("");

  // Per-rule table, sorted by delta_precision asc (worst regressions first),
  // then by (passes asc, rule_id) so failures float to the top.
  const sorted = [...snapshot.rules].sort((a, b) => {
    // Failing rules first
    if (a.passes !== b.passes) return a.passes ? 1 : -1;
    // Then regressed rules
    if (a.regressed !== b.regressed) return a.regressed ? -1 : 1;
    // Then worst precision-delta first
    if (a.delta_precision !== b.delta_precision) return a.delta_precision - b.delta_precision;
    return a.rule_id.localeCompare(b.rule_id);
  });

  lines.push("## Per-Rule Detail");
  lines.push("");
  lines.push("| Rule | Pass | Precision (measured / target) | Recall (measured / target) | Δ Prec | Δ Rec | TP / FN | TN / FP | Notes |");
  lines.push("|---|---|---|---|---|---|---|---|---|");
  for (const r of sorted) {
    const passBadge = r.passes ? "✅" : (r.regressed ? "🔴" : "⚠️");
    const targetR = r.target_recall === null ? "N/A" : pct(r.target_recall);
    const measuredR = r.target_recall === null ? "N/A" : pct(r.measured_recall);
    const deltaPrecFmt = r.baseline_delta ? "—" : deltaFmt(r.delta_precision);
    const deltaRecFmt = r.baseline_delta || r.target_recall === null ? "—" : deltaFmt(r.delta_recall);
    const notes: string[] = [];
    if (!r.passes_precision) notes.push("precision below target");
    if (!r.passes_recall) notes.push("recall below target");
    if (r.regressed) notes.push("regression vs prior snapshot");
    lines.push(
      `| ${r.rule_id} | ${passBadge} | ${pct(r.measured_precision)} / ${pct(r.target_precision)} | ` +
        `${measuredR} / ${targetR} | ${deltaPrecFmt} | ${deltaRecFmt} | ` +
        `${r.tp} / ${r.fn} | ${r.tn} / ${r.fp} | ${notes.join("; ") || "—"} |`
    );
  }
  lines.push("");

  // Regressions since last run
  lines.push("## Regressions Since Last Run");
  lines.push("");
  if (!priorSnapshot) {
    lines.push("_Baseline run — no prior snapshot to compare against._");
  } else if (a.regressions_count === 0) {
    lines.push("_No regressions detected._");
  } else {
    lines.push("| Rule | Metric | Prior | Now | Delta |");
    lines.push("|---|---|---|---|---|");
    for (const r of snapshot.rules.filter(x => x.regressed)) {
      const prior = priorSnapshot.rules.find(x => x.rule_id === r.rule_id);
      if (!prior) continue;
      if (r.delta_precision < -snapshot.regression_threshold) {
        lines.push(
          `| ${r.rule_id} | precision | ${pct(prior.measured_precision)} | ${pct(r.measured_precision)} | ${deltaFmt(r.delta_precision)} |`
        );
      }
      if (r.target_recall !== null && r.delta_recall < -snapshot.regression_threshold) {
        lines.push(
          `| ${r.rule_id} | recall | ${pct(prior.measured_recall)} | ${pct(r.measured_recall)} | ${deltaFmt(r.delta_recall)} |`
        );
      }
    }
  }
  lines.push("");

  // Below-target rules section (transparency — the "do not loosen the target" clause).
  const belowTarget = snapshot.rules.filter(r => !r.passes);
  if (belowTarget.length > 0) {
    lines.push("## Rules Below Target");
    lines.push("");
    lines.push(
      `${belowTarget.length} rule(s) measured below their declared target. ` +
        `This baseline is recorded as-is — targets are not lowered retroactively.`
    );
    lines.push("");
    lines.push("| Rule | Issue | Measured | Target |");
    lines.push("|---|---|---|---|");
    for (const r of belowTarget.sort((a, b) => a.rule_id.localeCompare(b.rule_id))) {
      if (!r.passes_precision) {
        lines.push(
          `| ${r.rule_id} | precision | ${pct(r.measured_precision)} | ${pct(r.target_precision)} |`
        );
      }
      if (!r.passes_recall) {
        lines.push(
          `| ${r.rule_id} | recall | ${pct(r.measured_recall)} | ${pct(r.target_recall ?? 0)} |`
        );
      }
    }
    lines.push("");
  }

  // Maturing rules — targets pinned at or near measured floor. Surfaced here
  // so a reviewer can raise them as follow-up work. Targets are ratcheted up
  // as the rule improves; they are never silently loosened.
  const maturing = snapshot.rules
    .filter(r => r.rationale.includes("pinned to measured floor"))
    .sort((a, b) => {
      const aScore = a.measured_precision * (a.target_recall === null ? 1 : a.measured_recall);
      const bScore = b.measured_precision * (b.target_recall === null ? 1 : b.measured_recall);
      return aScore - bScore;
    });
  if (maturing.length > 0) {
    lines.push("## Maturing Rules (Follow-Up Candidates)");
    lines.push("");
    lines.push(
      `${maturing.length} rule(s) have one or more targets pinned at the measured baseline. ` +
        `These are maturing rules — the target establishes a regression ratchet, and ` +
        `will be raised as detection logic improves. Listed worst-first by combined measured score.`
    );
    lines.push("");
    lines.push("| Rule | Measured Precision | Measured Recall | Target Precision | Target Recall |");
    lines.push("|---|---|---|---|---|");
    for (const r of maturing.slice(0, 40)) {
      lines.push(
        `| ${r.rule_id} | ${pct(r.measured_precision)} | ${pct(r.measured_recall)} | ` +
          `${pct(r.target_precision)} | ${r.target_recall === null ? "N/A" : pct(r.target_recall)} |`
      );
    }
    lines.push("");
  }

  lines.push("---");
  lines.push("");
  lines.push(`_Regression threshold: ${pct(snapshot.regression_threshold)} (per metric)_`);
  lines.push(`_Retired rules excluded: ${snapshot.retiredRules.join(", ")}_`);

  return lines.join("\n") + "\n";
}

// ── Persistence ─────────────────────────────────────────────────────────────

export interface WriteArtefactsOptions {
  latestPath: string;
  trendPath: string;
  snapshot: DashboardSnapshot;
  priorSnapshot: DashboardSnapshot | null;
}

/** Write latest.json + trend.md to disk. Creates parent dirs if absent. */
export function writeDashboardArtefacts(opts: WriteArtefactsOptions): void {
  ensureDir(dirname(opts.latestPath));
  ensureDir(dirname(opts.trendPath));
  writeFileSync(opts.latestPath, renderLatestJson(opts.snapshot) + "\n");
  writeFileSync(opts.trendPath, renderTrendMarkdown(opts.snapshot, opts.priorSnapshot));
}

/** Read a prior snapshot from disk, returning null if absent or malformed. */
export function readPriorSnapshot(path: string): DashboardSnapshot | null {
  if (!existsSync(path)) return null;
  try {
    const raw = readFileSync(path, "utf-8");
    // Allow trailing newline we add on write.
    return JSON.parse(raw) as DashboardSnapshot;
  } catch {
    return null;
  }
}

// ── Default paths (for CLI + workflow) ──────────────────────────────────────

const __dirnameDashboard = dirname(new URL(import.meta.url).pathname);
export const DEFAULT_DOCS_DIR = resolve(__dirnameDashboard, "../../../../docs/accuracy");
export const DEFAULT_LATEST_PATH = resolve(DEFAULT_DOCS_DIR, "latest.json");
export const DEFAULT_TREND_PATH = resolve(DEFAULT_DOCS_DIR, "trend.md");

// ── Utils ───────────────────────────────────────────────────────────────────

function round(v: number): number {
  return Math.round(v * 1000) / 1000;
}

function pct(v: number): string {
  return `${(v * 100).toFixed(1)}%`;
}

function deltaFmt(v: number): string {
  const sign = v >= 0 ? "+" : "";
  return `${sign}${(v * 100).toFixed(1)}pp`;
}

function ensureDir(d: string): void {
  if (!existsSync(d)) mkdirSync(d, { recursive: true });
}
