/**
 * view-model — server-side derivation for the five-entity cascade.
 *
 * Pure function. No hooks, no fetch, no React. The page calls
 * `buildViewModel(data)` once at request time and passes the result to
 * the client components, which become pure renderers.
 *
 * Why a view-model and not derive-on-the-fly:
 *   - Score, verdict, severity sort, and the (findings / skipped / clean)
 *     partition all need the same severity histogram. Computing it once
 *     here means the rule cards, header, and skipped block all read the
 *     same numbers. No drift.
 *   - The page is the only file that should know the shape of
 *     `DeepDiveData`. Once we cross into `<RuleCard/>`, props are minimal.
 *   - Score is derived from findings here — we do NOT read
 *     `data.audit_summary` because the audit panels are killed.
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
 *   time so they never surface in the skipped block as fake coverage gaps.
 */

import type {
  DeepDiveData,
  DeepDiveCategory,
  DeepDiveSubCategory,
  DeepDiveRule,
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

// Retired rules that may still appear in deep-dive payloads. Filtering
// here is defensive; the API should already exclude them via
// `enabled: false` in YAML.
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

// Rules that cap total score at 40 when they fire (lethal trifecta).
const LETHAL_TRIFECTA_RULE_IDS = new Set(["F1", "I13"]);

// ── View-model output shapes ──────────────────────────────────────────

export interface RuleWithFindings extends DeepDiveRule {
  /** Pre-computed: worst severity across this rule's findings. */
  worstSeverity: DeepDiveSeverity;
}

export interface SubCategoryWithFindings {
  id: string;
  title: string;
  summary: string;
  findingCount: number;
  worstSeverity: DeepDiveSeverity;
  rules: RuleWithFindings[];
}

export interface CategoryWithFindings {
  id: string;
  title: string;
  summary: string;
  frameworks: string[];
  findingCount: number;
  worstSeverity: DeepDiveSeverity;
  subCategories: SubCategoryWithFindings[];
}

export interface SkippedRule {
  rule: DeepDiveRule;
  categoryId: string;
  categoryTitle: string;
  subCategoryId: string;
  subCategoryTitle: string;
}

export interface SkippedGroup {
  /** Stable key built from missing_inputs (sorted + joined). */
  key: string;
  /** The set of missing inputs that defines this group. */
  missingInputs: DeepDiveSkipInput[];
  /** Human label for the CTA, e.g. "Source code". */
  label: string;
  rules: SkippedRule[];
}

export interface CleanCategory {
  id: string;
  title: string;
  rulesTotal: number;
}

export interface HeaderCounts {
  findings: number;
  skipped: number;
  passed: number;
  total: number;
}

export interface PageViewModel {
  findingsByCategory: CategoryWithFindings[];
  skipped: SkippedGroup[];
  cleanCategories: CleanCategory[];
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
): DeepDiveSeverity {
  if (severities.length === 0) return "informational";
  let worst = severities[0];
  for (const s of severities) {
    if (severityRank(s) > severityRank(worst)) worst = s;
  }
  return worst;
}

function isFindingsRule(r: DeepDiveRule): boolean {
  return r.status === "findings" && Array.isArray(r.findings) && r.findings.length > 0;
}

function isSkippedRule(r: DeepDiveRule): boolean {
  return r.status === "skipped";
}

function isRetired(r: DeepDiveRule): boolean {
  return RETIRED_RULE_IDS.has(r.rule_id);
}

function isCanonicalPlacement(r: DeepDiveRule): boolean {
  // `is_canonical` is optional. Default to true when absent — the API only
  // emits the flag on cross-reference placements where it's false.
  return r.is_canonical !== false;
}

// Skip-input label used in the CTA copy. Stable, deterministic.
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

  // Pass 1 — partition rules into (findings, skipped, passed) per
  // (category, sub-category). Retired rules and non-canonical placements
  // are dropped on the way in so they never surface anywhere.

  const findingsByCategory: CategoryWithFindings[] = [];
  const cleanCategories: CleanCategory[] = [];
  const skipped: SkippedRule[] = [];

  let findingsCount = 0;
  let skippedCount = 0;
  let passedCount = 0;
  let lethalTrifectaActive = false;

  for (const cat of categories) {
    if (!cat || typeof cat !== "object") continue;
    const subs: SubCategoryWithFindings[] = [];
    let catFindingCount = 0;
    const catSeverities: DeepDiveSeverity[] = [];

    const safeSubs = Array.isArray(cat.sub_categories) ? cat.sub_categories : [];

    for (const sub of safeSubs) {
      if (!sub || typeof sub !== "object") continue;
      const findingsRules: RuleWithFindings[] = [];
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
          findingsRules.push({ ...rule, worstSeverity: worst });
          findingsCount += rule.findings.length;
        } else if (isSkippedRule(rule)) {
          skipped.push({
            rule,
            categoryId: cat.id,
            categoryTitle: cat.title ?? cat.id,
            subCategoryId: sub.id,
            subCategoryTitle: sub.title ?? sub.id,
          });
          skippedCount += 1;
        } else {
          // status === "passed"
          passedCount += 1;
        }
      }

      if (findingsRules.length > 0) {
        // Sort rules within a sub-category: worst severity first, then
        // confidence desc, then rule id asc. The third key keeps the
        // order stable when rules tie on the first two.
        findingsRules.sort((a, b) => {
          const sevDiff = severityRank(b.worstSeverity) - severityRank(a.worstSeverity);
          if (sevDiff !== 0) return sevDiff;
          const confA = a.findings[0]?.confidence ?? 0;
          const confB = b.findings[0]?.confidence ?? 0;
          if (confA !== confB) return confB - confA;
          return a.rule_id.localeCompare(b.rule_id);
        });

        const subFindingCount = findingsRules.reduce(
          (n, r) => n + r.findings.length,
          0,
        );
        const subSeverities = findingsRules.map((r) => r.worstSeverity);
        const subWorst = worstSeverityOf(subSeverities);
        subs.push({
          id: sub.id,
          title: sub.title ?? sub.id,
          summary: sub.summary ?? "",
          findingCount: subFindingCount,
          worstSeverity: subWorst,
          rules: findingsRules,
        });
        catFindingCount += subFindingCount;
        catSeverities.push(subWorst);
      }
    }

    if (subs.length > 0) {
      // Sub-categories sorted by worst severity first.
      subs.sort(
        (a, b) => severityRank(b.worstSeverity) - severityRank(a.worstSeverity),
      );
      findingsByCategory.push({
        id: cat.id,
        title: cat.title ?? cat.id,
        summary: cat.summary ?? "",
        frameworks: Array.isArray(cat.frameworks) ? cat.frameworks : [],
        findingCount: catFindingCount,
        worstSeverity: worstSeverityOf(catSeverities),
        subCategories: subs,
      });
    } else {
      // No findings in any sub-category of this category — it's clean.
      // Use the category's own counts.rules_total when present, else
      // sum the per-sub totals (defensive).
      const rulesTotal =
        Number(cat.counts?.rules_total) ||
        safeSubs.reduce((n, s) => n + (Number(s?.counts?.rules_total) || 0), 0);
      cleanCategories.push({
        id: cat.id,
        title: cat.title ?? cat.id,
        rulesTotal,
      });
    }
  }

  // Category-level sort: worst severity first, then alphabetical title.
  findingsByCategory.sort((a, b) => {
    const sevDiff = severityRank(b.worstSeverity) - severityRank(a.worstSeverity);
    if (sevDiff !== 0) return sevDiff;
    return a.title.localeCompare(b.title);
  });

  // Clean categories use canonical taxonomy order — preserve the order
  // they arrived in `data.categories`. Build a position index then sort.
  const taxonomyOrder = new Map<string, number>();
  categories.forEach((c, i) => {
    if (c && typeof c === "object") taxonomyOrder.set(c.id, i);
  });
  cleanCategories.sort(
    (a, b) => (taxonomyOrder.get(a.id) ?? 0) - (taxonomyOrder.get(b.id) ?? 0),
  );

  // ── Score + verdict ──────────────────────────────────────────────

  // Penalty sum across every finding across every retained rule.
  let penalty = 0;
  let critical = 0;
  let high = 0;
  for (const cat of findingsByCategory) {
    for (const sub of cat.subCategories) {
      for (const rule of sub.rules) {
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
  for (const s of skipped) {
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
  // Within each group, sort by rule id for stable rendering.
  for (const g of skippedGroups) {
    g.rules.sort((a, b) => a.rule.rule_id.localeCompare(b.rule.rule_id));
  }

  // ── Counts ───────────────────────────────────────────────────────

  // `total` is the sum of executed + skipped rules. Some older scans
  // count skipped rules inside `rules_executed`; we recompute defensively
  // from our partition so the header always agrees with what's rendered.
  const total = findingsCount > 0 || skippedCount > 0 || passedCount > 0
    ? // sum of unique rules across the partition (findings counted by
      // RULE not finding count)
      (() => {
        let rules = 0;
        for (const cat of findingsByCategory) {
          for (const sub of cat.subCategories) rules += sub.rules.length;
        }
        return rules + skippedCount + passedCount;
      })()
    : Number(data.coverage?.total_rules) || 0;

  const counts: HeaderCounts = {
    findings: findingsCount,
    skipped: skippedCount,
    passed: passedCount,
    total,
  };

  return {
    findingsByCategory,
    skipped: skippedGroups,
    cleanCategories,
    counts,
    score,
    band,
    verdict,
    lethalTrifectaActive,
  };
}
