/**
 * Mutation auditor runner.
 *
 * For every registered TypedRuleV2 with ≥ 1 true-positive fixture:
 *   1. Compute a baseline finding count on the un-mutated fixture.
 *   2. Apply each of the 8 mutations to the fixture source text.
 *   3. Rebuild the AnalysisContext from the mutated text.
 *   4. Run the rule again and compare findings before/after.
 *
 * Outcomes are recorded with their numeric finding counts so the report is
 * falsifiable: a reviewer can re-run the suite and verify the same rule
 * produces the same count on the same mutation.
 *
 * Failure handling: any thrown error is captured as `outcome: "error"` with
 * the message in `detail`. The runner never throws up the call stack — it
 * walks every (rule, fixture, mutation) triple and emits a complete matrix.
 */

import { readdirSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, basename } from "node:path";
import {
  getAllTypedRulesV2,
  type TypedRuleV2,
} from "@mcp-sentinel/analyzer";
import { MUTATION_CATALOGUE } from "./mutations/index.js";
import {
  listTruePositiveFixtures,
  loadFixture,
  buildContextFromSource,
  classifyFixture,
  type LoadedFixture,
} from "./fixture-loader.js";
import type {
  MutationId,
  MutationOutcome,
  MutationReport,
  PerRuleSummary,
  MutationOutcomeLabel,
} from "./types.js";

export interface MutationRunOptions {
  /** Case-sensitive prefix match on rule id: "K1" or "C" (category). */
  ruleFilter?: string;
  /** Case-sensitive substring match on fixture filename. */
  fixtureFilter?: string;
  /**
   * If set, write the JSON report here and a sibling Markdown summary at
   * the same path with the .md extension.
   */
  writeReport?: string;
  /** Logger hook — defaults to stderr-only console.warn for noisy events. */
  onEvent?: (event: { type: "rule-start" | "fixture-error" | "mutation-error"; rule_id: string; detail?: string }) => void;
  /**
   * Optional override for the implementations directory. Tests use this to
   * point at a sandbox; production always uses the analyzer package.
   */
  implementationsDir?: string;
}

/**
 * Locate the rule directory for a given rule id. The repo's naming convention
 * is `<id-lower>-<kebab-description>` — e.g. `k1-absent-structured-logging`.
 * We scan the implementations directory once and index by id prefix so
 * lookups are O(1) afterwards.
 */
function buildRuleDirIndex(implementationsDir: string): Map<string, string> {
  const index = new Map<string, string>();
  if (!existsSync(implementationsDir)) return index;
  const entries = readdirSync(implementationsDir, { withFileTypes: true });
  for (const e of entries) {
    if (!e.isDirectory()) continue;
    if (e.name === "_shared") continue;
    // Extract the rule-id prefix up to the first dash.
    const match = e.name.match(/^([a-z]\d+)-/);
    if (!match) continue;
    const id = match[1].toUpperCase();
    index.set(id, join(implementationsDir, e.name));
  }
  return index;
}

/**
 * Resolve the implementations dir from this file's location. Works in
 * dev (tsx) and after compilation because we walk up from __dirname until we
 * find `packages/analyzer/src/rules/implementations`.
 */
function defaultImplementationsDir(): string {
  // The runner lives at packages/red-team/src/mutation/runner.ts; the
  // analyzer rules at packages/analyzer/src/rules/implementations. We walk
  // up until we find a `packages` directory, then descend.
  let dir = dirname(new URL(import.meta.url).pathname);
  for (let i = 0; i < 10; i++) {
    const candidate = join(dir, "packages", "analyzer", "src", "rules", "implementations");
    if (existsSync(candidate)) return candidate;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  throw new Error("could not locate packages/analyzer/src/rules/implementations from " + new URL(import.meta.url).pathname);
}

function runRule(rule: TypedRuleV2, fixture: LoadedFixture): { count: number; error?: string } {
  try {
    const ctx = fixture.buildContext();
    const results = rule.analyze(ctx);
    return { count: results.length };
  } catch (err) {
    return { count: 0, error: err instanceof Error ? err.message : String(err) };
  }
}

function runRuleOnMutation(rule: TypedRuleV2, fixture: LoadedFixture, mutatedSource: string): { count: number; error?: string } {
  try {
    const ctx = buildContextFromSource(mutatedSource, fixture.absPath, fixture.kind === "unknown" ? classifyFixture(mutatedSource, basename(fixture.absPath)) : fixture.kind);
    const results = rule.analyze(ctx);
    return { count: results.length };
  } catch (err) {
    return { count: 0, error: err instanceof Error ? err.message : String(err) };
  }
}

/**
 * Run the full mutation audit. Deterministic — no randomness, no parallel
 * execution, outcomes are emitted in rule-id × fixture × mutation order.
 */
export function runMutationAudit(options: MutationRunOptions = {}): MutationReport {
  const implementationsDir = options.implementationsDir ?? defaultImplementationsDir();
  const ruleDirIndex = buildRuleDirIndex(implementationsDir);

  const allRules = getAllTypedRulesV2().slice().sort((a, b) => a.id.localeCompare(b.id, "en"));
  const filtered = options.ruleFilter
    ? allRules.filter((r) => r.id.startsWith(options.ruleFilter!))
    : allRules;

  const outcomes: MutationOutcome[] = [];
  const perRule: PerRuleSummary[] = [];

  for (const rule of filtered) {
    options.onEvent?.({ type: "rule-start", rule_id: rule.id });
    const ruleDir = ruleDirIndex.get(rule.id);
    const fixtureFiles = ruleDir ? listTruePositiveFixtures(ruleDir) : [];
    const filteredFixtures = options.fixtureFilter
      ? fixtureFiles.filter((f) => basename(f).includes(options.fixtureFilter!))
      : fixtureFiles;

    if (filteredFixtures.length === 0) {
      perRule.push({
        rule_id: rule.id,
        survived: [],
        acknowledged_blind: [],
        not_applicable: [],
        errors: [],
        fixtures_without_baseline: [],
        no_fixtures: true,
      });
      continue;
    }

    // Aggregate survived / blind per rule. A mutation is "survived" if it
    // survived on AT LEAST ONE fixture whose baseline fires. It is "blind"
    // if it was blind on AT LEAST ONE fixture AND never survived. (This is
    // the defensible reading: any positive evidence of detection counts for
    // the rule; the charter's blind list records the cases where the rule
    // genuinely loses the signal.)
    const survivedSet = new Set<MutationId>();
    const blindSet = new Set<MutationId>();
    const naSet = new Set<MutationId>();
    const errSet = new Set<MutationId>();
    const fixturesWithoutBaseline: string[] = [];

    for (const fixtureAbs of filteredFixtures) {
      let fixture: LoadedFixture;
      try {
        fixture = loadFixture(fixtureAbs);
      } catch (err) {
        options.onEvent?.({
          type: "fixture-error",
          rule_id: rule.id,
          detail: `${basename(fixtureAbs)}: ${err instanceof Error ? err.message : String(err)}`,
        });
        continue;
      }

      // Baseline — unmutated.
      const baseline = runRule(rule, fixture);
      if (baseline.error) {
        options.onEvent?.({
          type: "fixture-error",
          rule_id: rule.id,
          detail: `${fixture.filename} baseline: ${baseline.error}`,
        });
      }
      if (baseline.count === 0) {
        fixturesWithoutBaseline.push(fixture.filename);
        // Still record per-mutation outcomes for debugging, but mark them
        // error / not-applicable so they don't contaminate the charter lists.
        for (const mut of MUTATION_CATALOGUE) {
          outcomes.push({
            rule_id: rule.id,
            fixture: fixture.filename,
            mutation: mut.id,
            outcome: "error",
            detail: "baseline did not fire — cannot audit mutation",
            findings_before: 0,
            findings_after: 0,
          });
        }
        continue;
      }

      for (const mut of MUTATION_CATALOGUE) {
        let mutatedSource: string;
        let notApplicable = false;
        try {
          const res = mut.apply(fixture.text);
          mutatedSource = res.mutated;
          if (res.notes === "not-applicable") notApplicable = true;
        } catch (err) {
          const label: MutationOutcomeLabel = "error";
          errSet.add(mut.id);
          outcomes.push({
            rule_id: rule.id,
            fixture: fixture.filename,
            mutation: mut.id,
            outcome: label,
            detail: `mutation threw: ${err instanceof Error ? err.message : String(err)}`,
            findings_before: baseline.count,
            findings_after: 0,
          });
          options.onEvent?.({
            type: "mutation-error",
            rule_id: rule.id,
            detail: `${fixture.filename}/${mut.id}: ${err instanceof Error ? err.message : String(err)}`,
          });
          continue;
        }

        if (notApplicable) {
          naSet.add(mut.id);
          outcomes.push({
            rule_id: rule.id,
            fixture: fixture.filename,
            mutation: mut.id,
            outcome: "not-applicable",
            findings_before: baseline.count,
            findings_after: baseline.count,
          });
          continue;
        }

        const after = runRuleOnMutation(rule, fixture, mutatedSource);
        if (after.error) {
          errSet.add(mut.id);
          outcomes.push({
            rule_id: rule.id,
            fixture: fixture.filename,
            mutation: mut.id,
            outcome: "error",
            detail: `rule threw on mutation: ${after.error}`,
            findings_before: baseline.count,
            findings_after: 0,
          });
          continue;
        }

        const label: MutationOutcomeLabel = after.count >= 1 ? "survived" : "blind";
        if (label === "survived") survivedSet.add(mut.id);
        else blindSet.add(mut.id);

        outcomes.push({
          rule_id: rule.id,
          fixture: fixture.filename,
          mutation: mut.id,
          outcome: label,
          findings_before: baseline.count,
          findings_after: after.count,
        });
      }
    }

    // Reconciliation: a mutation that ever survived is in `survived`. The
    // blind list is "was blind and never survived on any fixture". Errors
    // and not-applicable are reported separately, never on the charter.
    const survived: MutationId[] = [];
    const blind: MutationId[] = [];
    const notApplicableList: MutationId[] = [];
    const errorsList: MutationId[] = [];
    for (const mut of MUTATION_CATALOGUE) {
      if (survivedSet.has(mut.id)) survived.push(mut.id);
      else if (blindSet.has(mut.id)) blind.push(mut.id);
      else if (errSet.has(mut.id)) errorsList.push(mut.id);
      else if (naSet.has(mut.id)) notApplicableList.push(mut.id);
    }

    perRule.push({
      rule_id: rule.id,
      survived,
      acknowledged_blind: blind,
      not_applicable: notApplicableList,
      errors: errorsList,
      fixtures_without_baseline: fixturesWithoutBaseline,
      no_fixtures: false,
    });
  }

  const totals = computeTotals(filtered.length, perRule, outcomes);
  const report: MutationReport = {
    generated_at: new Date().toISOString(),
    rules_version: computeRulesVersion(),
    outcomes,
    per_rule_summary: perRule,
    totals,
  };

  if (options.writeReport) {
    const outPath = options.writeReport;
    mkdirSync(dirname(outPath), { recursive: true });
    writeFileSync(outPath, JSON.stringify(report, null, 2), "utf8");
    const md = renderMarkdownReport(report);
    const mdPath = outPath.replace(/\.json$/i, ".md");
    writeFileSync(mdPath === outPath ? outPath + ".md" : mdPath, md, "utf8");
  }

  return report;
}

function computeTotals(rulesTotal: number, perRule: PerRuleSummary[], outcomes: MutationOutcome[]): MutationReport["totals"] {
  let rulesWithFixtures = 0;
  let rulesSurvivedAny = 0;
  let rulesBlindAll = 0;
  for (const r of perRule) {
    if (r.no_fixtures) continue;
    rulesWithFixtures += 1;
    if (r.survived.length > 0) rulesSurvivedAny += 1;
    if (r.survived.length === 0 && r.acknowledged_blind.length > 0) rulesBlindAll += 1;
  }

  let survived = 0;
  let blind = 0;
  let na = 0;
  let err = 0;
  for (const o of outcomes) {
    if (o.outcome === "survived") survived += 1;
    else if (o.outcome === "blind") blind += 1;
    else if (o.outcome === "not-applicable") na += 1;
    else if (o.outcome === "error") err += 1;
  }
  return {
    rules_total: rulesTotal,
    rules_with_fixtures: rulesWithFixtures,
    rules_survived_any: rulesSurvivedAny,
    rules_blind_all: rulesBlindAll,
    mutation_cells_total: outcomes.length,
    mutation_cells_survived: survived,
    mutation_cells_blind: blind,
    mutation_cells_not_applicable: na,
    mutation_cells_errored: err,
  };
}

/**
 * Stand-in for getRulesVersion — the analyzer exposes one via rule-loader,
 * but importing it pulls in the full YAML loader which has no place here.
 * We use the count + sorted id list as a structural "version" signal so the
 * parity guard can detect "rules added since the baseline was frozen".
 */
function computeRulesVersion(): string {
  const ids = getAllTypedRulesV2().map((r) => r.id).sort().join(",");
  // Simple fnv-like hash — stable across runs, no dependency on cryptoi/crypto.
  let h = 2166136261;
  for (let i = 0; i < ids.length; i++) {
    h ^= ids.charCodeAt(i);
    h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
  }
  return `typed-v2-${getAllTypedRulesV2().length}-${h.toString(16)}`;
}

export function renderMarkdownReport(report: MutationReport): string {
  const lines: string[] = [];
  lines.push("# Mutation Audit — Latest");
  lines.push("");
  lines.push(`Generated: ${report.generated_at}`);
  lines.push(`Rules version: \`${report.rules_version}\``);
  lines.push("");
  lines.push("## Totals");
  lines.push("");
  lines.push("| Metric | Value |");
  lines.push("| --- | --- |");
  lines.push(`| rules_total | ${report.totals.rules_total} |`);
  lines.push(`| rules_with_fixtures | ${report.totals.rules_with_fixtures} |`);
  lines.push(`| rules_survived_any | ${report.totals.rules_survived_any} |`);
  lines.push(`| rules_blind_all | ${report.totals.rules_blind_all} |`);
  lines.push(`| cells_total | ${report.totals.mutation_cells_total} |`);
  lines.push(`| cells_survived | ${report.totals.mutation_cells_survived} |`);
  lines.push(`| cells_blind | ${report.totals.mutation_cells_blind} |`);
  lines.push(`| cells_not_applicable | ${report.totals.mutation_cells_not_applicable} |`);
  lines.push(`| cells_errored | ${report.totals.mutation_cells_errored} |`);
  const survRate = report.totals.mutation_cells_survived + report.totals.mutation_cells_blind;
  if (survRate > 0) {
    const rate = ((report.totals.mutation_cells_survived / survRate) * 100).toFixed(1);
    lines.push(`| aggregate_survival_rate | ${rate}% |`);
  }
  lines.push("");
  lines.push("## Per-rule summary");
  lines.push("");
  lines.push("| Rule | Survived | Blind | N/A | Errors | No fixtures | Baseline-miss fixtures |");
  lines.push("| --- | --- | --- | --- | --- | --- | --- |");
  for (const r of report.per_rule_summary) {
    lines.push(
      `| ${r.rule_id} | ${r.survived.join(", ")} | ${r.acknowledged_blind.join(", ")} | ${r.not_applicable.join(", ")} | ${r.errors.join(", ")} | ${r.no_fixtures ? "yes" : ""} | ${r.fixtures_without_baseline.join(", ")} |`,
    );
  }
  lines.push("");
  return lines.join("\n");
}
