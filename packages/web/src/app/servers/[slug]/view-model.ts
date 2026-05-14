/**
 * view-model — server-side derivation for the five-entity cascade.
 *
 * Pure function. No hooks, no fetch, no React. The page calls
 * `buildViewModel(data)` once at request time and passes the result to
 * the client components, which become pure renderers.
 *
 * The cascade is COMPLETE: every category, every sub-category, every
 * rule renders regardless of `status`. Findings rules surface their
 * evidence chains; passed rules surface "Tested cleanly"; skipped
 * rules surface "Needs <missing inputs>". The page IS the testing
 * taxonomy — for a clean server, the cascade is the proof of work.
 *
 * Score algorithm (matches `agent_docs/scoring-algorithm.md`):
 *   score = 100 − Σ(severity weight × finding count), floored at 0.
 *   Critical −25, High −15, Medium −8, Low −3, Info −1.
 *   Lethal trifecta (F1) and Cross-Config Lethal Trifecta (I13) cap at 40.
 *
 * Verdict pill:
 *   ≥1 critical finding → "RISK"
 *   ≥1 high finding     → "CAUTION"
 *   else                → "SAFE"
 *
 * Retired-rule filter:
 *   13 rules retired in 2026 with `enabled: false` in YAML. If the API
 *   still emits them in deep-dive (defensive), drop them at partition
 *   time so they never surface anywhere.
 */

import type {
  DeepDiveData,
  DeepDiveCategory,
  DeepDiveRule,
  DeepDiveRuleStatus,
  DeepDiveSeverity,
  DeepDiveSkipInput,
  AuditVerdictPill,
} from "@/lib/deep-dive";
import { scoreBand, type ScoreBand } from "@/lib/score-band";

// ── Severity weights (match scoring-algorithm.md) ─────────────────────

const SEVERITY_PENALTY: Record<DeepDiveSeverity, number> = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
  informational: 1,
};

const SEVERITY_RANK: Record<DeepDiveSeverity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  informational: 1,
};

// status ordering — findings rules rendered first so the most
// actionable rows in a sub-category land at the top.
const STATUS_RANK: Record<DeepDiveRuleStatus, number> = {
  findings: 3,
  skipped: 2,
  passed: 1,
};

const RETIRED_RULE_IDS = new Set([
  "O1",
  "O2",
  "O3",
  "O7",
  "Q1",
  "Q2",
  "Q5",
  "Q8",
  "Q9",
  "Q11",
  "Q12",
  "Q14",
  "M3",
]);

const LETHAL_TRIFECTA_RULE_IDS = new Set(["F1", "I13"]);

// ── View-model output shapes ──────────────────────────────────────────

export interface SeverityHistogram {
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
}

/**
 * A rule as it surfaces in the cascade — preserves its DeepDiveRule
 * shape and adds the worst-severity rollup of its findings (null when
 * the rule has no findings, e.g. passed / skipped).
 */
export interface CascadeRule extends DeepDiveRule {
  worstSeverity: DeepDiveSeverity | null;
}

export interface CascadeSubCategory {
  id: string;
  title: string;
  summary: string;
  /** Total findings across all rules in this sub-category. */
  findingCount: number;
  /** Rule status counts for the sub-category header. */
  ruleCounts: {
    findings: number;
    passed: number;
    skipped: number;
    total: number;
  };
  /** Highest severity across this sub-category's findings; null when clean. */
  worstSeverity: DeepDiveSeverity | null;
  severity: SeverityHistogram;
  rules: CascadeRule[];
}

export interface CascadeCategory {
  id: string;
  title: string;
  summary: string;
  frameworks: string[];
  findingCount: number;
  ruleCounts: {
    findings: number;
    passed: number;
    skipped: number;
    total: number;
  };
  worstSeverity: DeepDiveSeverity | null;
  severity: SeverityHistogram;
  subCategories: CascadeSubCategory[];
}

export interface SkippedRulePointer {
  rule: DeepDiveRule;
  categoryId: string;
  categoryTitle: string;
  subCategoryId: string;
  subCategoryTitle: string;
}

export interface SkippedGroup {
  key: string;
  missingInputs: DeepDiveSkipInput[];
  label: string;
  rules: SkippedRulePointer[];
}

export interface HeaderCounts {
  findings: number;
  skipped: number;
  passed: number;
  total: number;
}

export interface PageViewModel {
  /** Every category renders, with every rule under it (any status). */
  cascade: CascadeCategory[];
  /** Skipped groupings for the "Coverage gaps" CTA banner. */
  skipped: SkippedGroup[];
  counts: HeaderCounts;
  score: number;
  band: ScoreBand;
  verdict: AuditVerdictPill;
  /** True when the lethal trifecta capped the score at 40. */
  lethalTrifectaActive: boolean;
}

// ── Helpers ───────────────────────────────────────────────────────────

function severityRank(sev: DeepDiveSeverity): number {
  return SEVERITY_RANK[sev] ?? 0;
}

function worstSeverityOf(
  severities: DeepDiveSeverity[],
): DeepDiveSeverity | null {
  if (severities.length === 0) return null;
  let worst = severities[0];
  for (const s of severities) {
    if (severityRank(s) > severityRank(worst)) worst = s;
  }
  return worst;
}

function emptyHistogram(): SeverityHistogram {
  return { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
}

function bumpHistogram(hist: SeverityHistogram, sev: DeepDiveSeverity): void {
  hist[sev] += 1;
}

function addHistogram(a: SeverityHistogram, b: SeverityHistogram): SeverityHistogram {
  return {
    critical: a.critical + b.critical,
    high: a.high + b.high,
    medium: a.medium + b.medium,
    low: a.low + b.low,
    informational: a.informational + b.informational,
  };
}

function isFindingsRule(r: DeepDiveRule): boolean {
  return (
    r.status === "findings" &&
    Array.isArray(r.findings) &&
    r.findings.length > 0
  );
}

function isSkippedRule(r: DeepDiveRule): boolean {
  return r.status === "skipped";
}

function isRetired(r: DeepDiveRule): boolean {
  return RETIRED_RULE_IDS.has(r.rule_id);
}

function isCanonicalPlacement(r: DeepDiveRule): boolean {
  return r.is_canonical !== false;
}

function skipInputLabel(input: DeepDiveSkipInput): string {
  switch (input) {
    case "source_code":
      return "Source code";
    case "connection":
      return "Live connection";
    case "dependencies":
      return "Dependency manifest";
  }
}

function groupKey(inputs: DeepDiveSkipInput[]): string {
  return [...inputs].sort().join("+") || "unknown";
}

// ── Main builder ──────────────────────────────────────────────────────

export function buildViewModel(data: DeepDiveData): PageViewModel {
  const categories: DeepDiveCategory[] = Array.isArray(data.categories)
    ? data.categories
    : [];

  const cascade: CascadeCategory[] = [];
  const skippedFlat: SkippedRulePointer[] = [];

  let findingsCount = 0;
  let skippedCount = 0;
  let passedCount = 0;
  let lethalTrifectaActive = false;

  for (const cat of categories) {
    if (!cat || typeof cat !== "object") continue;
    const subs: CascadeSubCategory[] = [];
    let catFindingCount = 0;
    const catSeverities: DeepDiveSeverity[] = [];
    const catCounts = { findings: 0, passed: 0, skipped: 0, total: 0 };

    const safeSubs = Array.isArray(cat.sub_categories) ? cat.sub_categories : [];

    for (const sub of safeSubs) {
      if (!sub || typeof sub !== "object") continue;
      const subRules: CascadeRule[] = [];
      const subCounts = { findings: 0, passed: 0, skipped: 0, total: 0 };
      const subHistogram = emptyHistogram();
      let subFindingCount = 0;
      const subSeverities: DeepDiveSeverity[] = [];

      const safeRules = Array.isArray(sub.rules) ? sub.rules : [];

      for (const rule of safeRules) {
        if (!rule || typeof rule !== "object") continue;
        if (isRetired(rule)) continue;
        if (!isCanonicalPlacement(rule)) continue;

        if (isFindingsRule(rule)) {
          if (LETHAL_TRIFECTA_RULE_IDS.has(rule.rule_id)) {
            lethalTrifectaActive = true;
          }
          const severities = rule.findings.map((f) => f.severity);
          const worst = worstSeverityOf(severities);
          subRules.push({ ...rule, worstSeverity: worst });
          subFindingCount += rule.findings.length;
          findingsCount += rule.findings.length;
          subCounts.findings += 1;
          catCounts.findings += 1;
          for (const f of rule.findings) bumpHistogram(subHistogram, f.severity);
          if (worst !== null) subSeverities.push(worst);
        } else if (isSkippedRule(rule)) {
          subRules.push({ ...rule, worstSeverity: null });
          skippedFlat.push({
            rule,
            categoryId: cat.id,
            categoryTitle: cat.title ?? cat.id,
            subCategoryId: sub.id,
            subCategoryTitle: sub.title ?? sub.id,
          });
          skippedCount += 1;
          subCounts.skipped += 1;
          catCounts.skipped += 1;
        } else {
          // status === "passed"
          subRules.push({ ...rule, worstSeverity: null });
          passedCount += 1;
          subCounts.passed += 1;
          catCounts.passed += 1;
        }
        subCounts.total += 1;
        catCounts.total += 1;
      }

      if (subRules.length === 0) continue;

      // Sort rules: findings first (severity-descending), then skipped,
      // then passed. Within each status: rule id asc for stability.
      subRules.sort((a, b) => {
        const statusDiff = STATUS_RANK[b.status] - STATUS_RANK[a.status];
        if (statusDiff !== 0) return statusDiff;
        const sevA = a.worstSeverity;
        const sevB = b.worstSeverity;
        if (sevA && sevB && sevA !== sevB) {
          return severityRank(sevB) - severityRank(sevA);
        }
        return a.rule_id.localeCompare(b.rule_id);
      });

      const subWorst = worstSeverityOf(subSeverities);
      subs.push({
        id: sub.id,
        title: sub.title ?? sub.id,
        summary: sub.summary ?? "",
        findingCount: subFindingCount,
        ruleCounts: subCounts,
        worstSeverity: subWorst,
        severity: subHistogram,
        rules: subRules,
      });
      catFindingCount += subFindingCount;
      if (subWorst !== null) catSeverities.push(subWorst);
    }

    if (subs.length === 0) continue;

    // Sub-categories sorted by worst severity first (clean ones drop to the
    // bottom). Within equal severity, alphabetical title.
    subs.sort((a, b) => {
      const aw = a.worstSeverity;
      const bw = b.worstSeverity;
      if (aw && bw && aw !== bw) {
        return severityRank(bw) - severityRank(aw);
      }
      if (aw && !bw) return -1;
      if (!aw && bw) return 1;
      return a.title.localeCompare(b.title);
    });

    const catHistogram = subs.reduce(
      (acc, s) => addHistogram(acc, s.severity),
      emptyHistogram(),
    );

    cascade.push({
      id: cat.id,
      title: cat.title ?? cat.id,
      summary: cat.summary ?? "",
      frameworks: Array.isArray(cat.frameworks) ? cat.frameworks : [],
      findingCount: catFindingCount,
      ruleCounts: catCounts,
      worstSeverity: worstSeverityOf(catSeverities),
      severity: catHistogram,
      subCategories: subs,
    });
  }

  // Top-level category sort: worst severity first, clean categories at
  // the bottom but in their original taxonomy order. We sort in two
  // phases: severity-bearing categories alphabetically within their
  // severity, then clean ones in taxonomy order.
  const taxonomyOrder = new Map<string, number>();
  categories.forEach((c, i) => {
    if (c && typeof c === "object") taxonomyOrder.set(c.id, i);
  });
  cascade.sort((a, b) => {
    const aw = a.worstSeverity;
    const bw = b.worstSeverity;
    if (aw && bw && aw !== bw) {
      return severityRank(bw) - severityRank(aw);
    }
    if (aw && !bw) return -1;
    if (!aw && bw) return 1;
    if (!aw && !bw) {
      return (taxonomyOrder.get(a.id) ?? 0) - (taxonomyOrder.get(b.id) ?? 0);
    }
    return a.title.localeCompare(b.title);
  });

  // ── Score + verdict ──────────────────────────────────────────────

  let penalty = 0;
  let critical = 0;
  let high = 0;
  for (const cat of cascade) {
    for (const sub of cat.subCategories) {
      for (const rule of sub.rules) {
        if (rule.status !== "findings") continue;
        for (const f of rule.findings) {
          penalty += SEVERITY_PENALTY[f.severity] ?? 0;
          if (f.severity === "critical") critical += 1;
          else if (f.severity === "high") high += 1;
        }
      }
    }
  }
  let score = Math.max(0, Math.min(100, 100 - penalty));
  if (lethalTrifectaActive && score > 40) score = 40;

  const verdict: AuditVerdictPill =
    critical > 0 ? "RISK" : high > 0 ? "CAUTION" : "SAFE";
  const band: ScoreBand = scoreBand(score);

  // ── Skipped groups ───────────────────────────────────────────────

  const skippedGroupMap = new Map<string, SkippedGroup>();
  for (const s of skippedFlat) {
    const inputs = Array.isArray(s.rule.skip_reason?.missing_inputs)
      ? [...new Set(s.rule.skip_reason!.missing_inputs)]
      : [];
    const key = groupKey(inputs);
    let group = skippedGroupMap.get(key);
    if (!group) {
      const label =
        inputs.length === 0
          ? "Other"
          : inputs.map(skipInputLabel).join(" + ");
      group = { key, missingInputs: inputs, label, rules: [] };
      skippedGroupMap.set(key, group);
    }
    group.rules.push(s);
  }
  const skippedGroups = [...skippedGroupMap.values()].sort((a, b) =>
    a.label.localeCompare(b.label),
  );
  for (const g of skippedGroups) {
    g.rules.sort((a, b) => a.rule.rule_id.localeCompare(b.rule.rule_id));
  }

  // ── Counts (always defensive vs coverage payload) ────────────────

  let totalRules = 0;
  for (const cat of cascade) totalRules += cat.ruleCounts.total;
  if (totalRules === 0) {
    totalRules = Number(data.coverage?.total_rules) || 0;
  }

  return {
    cascade,
    skipped: skippedGroups,
    counts: {
      findings: findingsCount,
      skipped: skippedCount,
      passed: passedCount,
      total: totalRules,
    },
    score,
    band,
    verdict,
    lethalTrifectaActive,
  };
}
