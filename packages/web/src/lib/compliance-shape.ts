/**
 * compliance-shape.ts — Pure transformer that re-shapes the deep-dive
 * payload from `categories[]` into `frameworks[]` (the spine of the
 * Compliance lens).
 *
 * Compliance officers think in framework controls (EU AI Act Article 14,
 * ISO 27001 A.5.15, OWASP MCP01, …), not rule categories. This module
 * walks every rule's `framework_controls[]` cross-walk, groups by
 * framework_id → control_id, and emits a per-control summary with the
 * mechanical status derivation that mirrors
 * `packages/compliance-reports/src/build-report.ts`.
 *
 * Pure function — no DOM, no fetch, no async. Same inputs → byte-equal
 * output. Determinism contract is asserted in the tests so a regulator
 * can reproduce the page byte-for-byte from a captured response.
 *
 * Status derivation (per control):
 *   met            — every rule attached to this control has status
 *                    "passed". Honest "fully met" signal.
 *   unmet          — at least one rule has status "findings" with a
 *                    finding at the unmet-threshold severity (default:
 *                    high or critical). Mirrors the compliance-reports
 *                    package's unmet_threshold semantic.
 *   partial        — there are findings but none at the unmet threshold,
 *                    OR a mix of passed + findings below threshold.
 *   not_applicable — every rule is "skipped" (the control's inputs were
 *                    not available on this scan). Honest gap, never an
 *                    invented "met" claim.
 *
 * Framework display ordering is stable: alphabetical by `framework_id`.
 * Within a framework, controls are sorted by `control_id` lexicographically
 * with a numeric-aware tweak so "MCP02" lands after "MCP01" (not after
 * "MCP10" as a naive string sort would produce).
 */

import type { DeepDiveCategory, DeepDiveRule } from "./deep-dive";

export type ComplianceStatus =
  | "met"
  | "unmet"
  | "partial"
  | "not_applicable";

export interface ComplianceRuleRef {
  rule_id: string;
  name: string;
  status: DeepDiveRule["status"];
  /** Number of findings under this rule on the current scan. */
  findings_count: number;
  /** Highest severity of any finding (null when no findings). */
  worst_severity: DeepDiveRule["severity"] | null;
  /** Categorical letter (C / D / I / J / K / …) — useful for filters. */
  category: string;
}

export interface ComplianceControl {
  control_id: string;
  control_title: string;
  status: ComplianceStatus;
  /** Rules that map to this control under this framework. */
  rules: ComplianceRuleRef[];
  counts: {
    rules_total: number;
    rules_passed: number;
    rules_with_findings: number;
    rules_skipped: number;
    finding_count: number;
  };
}

export interface ComplianceFramework {
  framework_id: string;
  framework_label: string;
  controls: ComplianceControl[];
  counts: {
    controls_total: number;
    controls_met: number;
    controls_unmet: number;
    controls_partial: number;
    controls_not_applicable: number;
  };
}

const FRAMEWORK_LABELS: Record<string, string> = {
  eu_ai_act: "EU AI Act",
  iso_27001: "ISO 27001",
  owasp_mcp: "OWASP MCP Top 10",
  owasp_asi: "OWASP Agentic Top 10",
  cosai_mcp: "CoSAI MCP Security",
  maestro: "MAESTRO",
  mitre_atlas: "MITRE ATLAS",
};

/**
 * Severity rank. Higher number = more severe. Used for `worst_severity`
 * derivation and for the unmet-threshold check.
 */
const SEVERITY_RANK: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  informational: 1,
};

/**
 * Severities at or above this rank flip a control to "unmet" when
 * present. Mirrors the compliance-reports package default of
 * "high or critical" (Article 12-style record-keeping uses lower
 * thresholds; we keep the API contract simple here and use the
 * conservative high-or-critical default).
 */
const UNMET_THRESHOLD_RANK = SEVERITY_RANK["high"]!;

/**
 * Numeric-aware control-id sort. `MCP02` < `MCP10` instead of the naive
 * string comparison that puts `MCP10` before `MCP2`. Falls back to
 * locale-aware compare when the ids don't end in a number.
 */
function compareControlId(a: string, b: string): number {
  // Use Intl.Collator's numeric option for natural sort.
  // localeCompare with `numeric: true` handles "MCP02" vs "MCP10" correctly.
  return a.localeCompare(b, undefined, { numeric: true, sensitivity: "base" });
}

/** Walk every category → sub-category → rule and dedupe by rule_id. */
function flattenRules(
  categories: ReadonlyArray<DeepDiveCategory>,
): Map<string, DeepDiveRule> {
  const out = new Map<string, DeepDiveRule>();
  for (const cat of categories) {
    if (!cat || !Array.isArray(cat.sub_categories)) continue;
    for (const sub of cat.sub_categories) {
      if (!sub || !Array.isArray(sub.rules)) continue;
      for (const rule of sub.rules) {
        if (!rule || typeof rule.rule_id !== "string") continue;
        // First occurrence wins — cross-references emit the same rule
        // multiple times and we only want it counted once.
        if (!out.has(rule.rule_id)) out.set(rule.rule_id, rule);
      }
    }
  }
  return out;
}

function deriveControlStatus(rules: ComplianceRuleRef[]): ComplianceStatus {
  if (rules.length === 0) return "not_applicable";
  let allSkipped = true;
  let anyFindings = false;
  let anyAtUnmetThreshold = false;
  let anyPassed = false;
  for (const r of rules) {
    if (r.status !== "skipped") allSkipped = false;
    if (r.status === "passed") anyPassed = true;
    if (r.status === "findings") {
      anyFindings = true;
      const wsRank = r.worst_severity
        ? SEVERITY_RANK[r.worst_severity] ?? 0
        : 0;
      if (wsRank >= UNMET_THRESHOLD_RANK) anyAtUnmetThreshold = true;
    }
  }
  if (allSkipped) return "not_applicable";
  if (anyAtUnmetThreshold) return "unmet";
  if (anyFindings) return "partial";
  // No findings at all — but we know not all are skipped (allSkipped
  // was false above), so at least one passed. That's "met".
  if (anyPassed) return "met";
  // Defensive: shouldn't reach here, but be honest if we do.
  return "not_applicable";
}

function worstSeverityOfRule(
  rule: DeepDiveRule,
): DeepDiveRule["severity"] | null {
  const findings = Array.isArray(rule.findings) ? rule.findings : [];
  if (findings.length === 0) return null;
  let bestRank = 0;
  let best: DeepDiveRule["severity"] | null = null;
  for (const f of findings) {
    const r = SEVERITY_RANK[f.severity] ?? 0;
    if (r > bestRank) {
      bestRank = r;
      best = f.severity;
    }
  }
  return best;
}

function countsFor(rules: ComplianceRuleRef[]): ComplianceControl["counts"] {
  let passed = 0;
  let withFindings = 0;
  let skipped = 0;
  let findingCount = 0;
  for (const r of rules) {
    if (r.status === "passed") passed++;
    else if (r.status === "findings") withFindings++;
    else if (r.status === "skipped") skipped++;
    findingCount += r.findings_count;
  }
  return {
    rules_total: rules.length,
    rules_passed: passed,
    rules_with_findings: withFindings,
    rules_skipped: skipped,
    finding_count: findingCount,
  };
}

/**
 * Reshape the deep-dive categories into a frameworks list grouped by
 * framework_id → control_id. Pure function — same inputs always yield
 * byte-equal output (test asserts JSON.stringify equality across calls).
 */
export function buildComplianceShape(
  categories: ReadonlyArray<DeepDiveCategory> | undefined,
): ComplianceFramework[] {
  if (!categories || categories.length === 0) return [];
  const allRules = flattenRules(categories);

  // framework_id → (control_id → { control_title, rules[] })
  const grouped = new Map<
    string,
    Map<string, { control_title: string; rules: ComplianceRuleRef[] }>
  >();

  for (const rule of allRules.values()) {
    if (!Array.isArray(rule.framework_controls)) continue;
    const ref: ComplianceRuleRef = {
      rule_id: rule.rule_id,
      name: rule.name,
      status: rule.status,
      findings_count: Array.isArray(rule.findings) ? rule.findings.length : 0,
      worst_severity: worstSeverityOfRule(rule),
      category: rule.category,
    };
    for (const fc of rule.framework_controls) {
      if (
        !fc ||
        typeof fc.framework_id !== "string" ||
        typeof fc.control_id !== "string"
      ) {
        continue;
      }
      let fwBucket = grouped.get(fc.framework_id);
      if (!fwBucket) {
        fwBucket = new Map();
        grouped.set(fc.framework_id, fwBucket);
      }
      let ctrl = fwBucket.get(fc.control_id);
      if (!ctrl) {
        ctrl = {
          control_title:
            typeof fc.control_title === "string" ? fc.control_title : fc.control_id,
          rules: [],
        };
        fwBucket.set(fc.control_id, ctrl);
      }
      // Dedupe — a rule that lists the same control twice should only
      // appear once.
      if (!ctrl.rules.some((r) => r.rule_id === ref.rule_id)) {
        ctrl.rules.push(ref);
      }
    }
  }

  // Materialise into the public shape, sorted deterministically.
  const out: ComplianceFramework[] = [];
  const sortedFrameworkIds = Array.from(grouped.keys()).sort();
  for (const fwId of sortedFrameworkIds) {
    const fwBucket = grouped.get(fwId)!;
    const sortedControlIds = Array.from(fwBucket.keys()).sort(compareControlId);
    const controls: ComplianceControl[] = [];
    for (const ctrlId of sortedControlIds) {
      const c = fwBucket.get(ctrlId)!;
      // Sort rules within the control by category letter then rule id
      // (numeric-aware) so the same control always renders the same
      // rule order across runs.
      const sortedRules = [...c.rules].sort((a, b) => {
        if (a.category !== b.category) {
          return a.category.localeCompare(b.category);
        }
        return compareControlId(a.rule_id, b.rule_id);
      });
      controls.push({
        control_id: ctrlId,
        control_title: c.control_title,
        status: deriveControlStatus(sortedRules),
        rules: sortedRules,
        counts: countsFor(sortedRules),
      });
    }
    let met = 0;
    let unmet = 0;
    let partial = 0;
    let na = 0;
    for (const c of controls) {
      if (c.status === "met") met++;
      else if (c.status === "unmet") unmet++;
      else if (c.status === "partial") partial++;
      else na++;
    }
    out.push({
      framework_id: fwId,
      framework_label: FRAMEWORK_LABELS[fwId] ?? fwId,
      controls,
      counts: {
        controls_total: controls.length,
        controls_met: met,
        controls_unmet: unmet,
        controls_partial: partial,
        controls_not_applicable: na,
      },
    });
  }

  return out;
}
