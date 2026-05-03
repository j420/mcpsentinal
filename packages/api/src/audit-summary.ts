/**
 * Audit Summary — Senior Security Architect verdict layer (Phase 2 of the
 * server detail page redesign).
 *
 * Pure, deterministic synthesis of the 8-section enterprise-grade audit
 * verdict from data the deep-dive endpoint already loads. No new DB calls.
 * No LLM (deterministic only per ADR-006). Idempotent — same inputs always
 * produce byte-equivalent output, which is critical for the SWR cache.
 *
 * Section map (matches the redesign brief):
 *   §1 verdict             — SAFE / CAUTION / RISK pill + score + reasons + worst case
 *   §2 testing_depth       — categories + tests count + inputs + HIGH/MEDIUM/LOW
 *   §3 attack_intelligence — top 3-5 chains with source→propagation→sink + outcome
 *   §4 risk_summary        — per-category SAFE/CAUTION/UNKNOWN pills
 *   §5 gaps                — skipped rules + missing inputs + LOW/MEDIUM/HIGH impact
 *   §6 recommendation      — YES/CONDITIONAL/NO + conditions + auditable rationale
 *   §7 confidence          — HIGH/MEDIUM/LOW + factors
 *   §8 evidence_trust      — runtime + e2e preserved + signed receipt URL pattern
 *
 * Conservative bias throughout: when two heuristics disagree, the more
 * restrictive wins. RISK > CAUTION > SAFE; NO > CONDITIONAL > YES. This is
 * a regulator-grade decision surface — over-flagging is recoverable; under-
 * flagging a real risk is not.
 */

import type {
  AnalysisCoverage,
  AuditAttackOutcome,
  AuditAttackScenario,
  AuditCategoryStatus,
  AuditConfidence,
  AuditConfidenceLevel,
  AuditCoverageLevel,
  AuditEvidenceTrust,
  AuditGap,
  AuditImpact,
  AuditRecommendation,
  AuditRecommendationDecision,
  AuditRiskSummary,
  AuditScoreBand,
  AuditSummary,
  AuditTestingDepth,
  AuditVerdict,
  AuditVerdictPill,
  DeepDiveCategory,
  DeepDiveResponse,
  DeepDiveRule,
  Finding,
  Severity,
} from "@mcp-sentinel/database";
import type { DeepDiveAttackChain } from "./deep-dive.js";

// ─── Public API ─────────────────────────────────────────────────────────────

export interface BuildAuditSummaryInput {
  /** The already-assembled core deep-dive shape (server + coverage + categories). */
  deepDive: DeepDiveResponse;
  /**
   * Latest score row from `getLatestScoreForServer`. May be null when the
   * server has never been scanned — the audit summary still renders, but
   * with conservative defaults (verdict=RISK, recommendation=NO).
   */
  score: {
    total_score: number;
    coverage_band: "high" | "medium" | "low" | "minimal" | null;
    analysis_coverage: AnalysisCoverage | null;
  } | null;
  /**
   * Raw findings for the latest scan. Used for §1 worst_case derivation
   * (top critical finding's evidence) and §8 e2e chain preservation check.
   */
  findings: Finding[];
  /** Optional kill chains from `getAttackChainsForServer`. Drives §3. */
  attackChains?: DeepDiveAttackChain[];
}

/**
 * Produce the full §1-§8 audit summary. Pure function — call this from the
 * deep-dive route handler after `buildDeepDive` has assembled the core
 * response.
 */
export function buildAuditSummary(input: BuildAuditSummaryInput): AuditSummary {
  const verdict = deriveVerdict(input);
  const testingDepth = deriveTestingDepth(input);
  const attackIntel = deriveAttackIntelligence(input);
  const riskSummary = deriveRiskSummary(input);
  const gaps = deriveGaps(input);
  const confidence = deriveConfidence(input, testingDepth);
  // recommendation depends on attackIntel + confidence — derive last so the
  // decision tree can read upstream signals without re-computing them.
  const recommendation = deriveRecommendation(input, attackIntel, confidence);
  const evidenceTrust = deriveEvidenceTrust(input);

  return {
    verdict,
    testing_depth: testingDepth,
    attack_intelligence: attackIntel,
    risk_summary: riskSummary,
    gaps,
    recommendation,
    confidence,
    evidence_trust: evidenceTrust,
  };
}

// ─── §1 Verdict ─────────────────────────────────────────────────────────────

/** Score-band thresholds — must match `EvidenceSummaryHero.tsx:99` (canonical). */
export function scoreBand(score: number): AuditScoreBand {
  if (score >= 80) return "good";
  if (score >= 60) return "moderate";
  if (score >= 40) return "poor";
  return "critical";
}

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  informational: 1,
};

function hasFindingAtOrAbove(findings: Finding[], minRank: number): boolean {
  return findings.some((f) => (SEVERITY_RANK[f.severity] ?? 0) >= minRank);
}

function deriveVerdict(input: BuildAuditSummaryInput): AuditVerdict {
  const totalScore = input.score?.total_score ?? 0;
  const band = scoreBand(totalScore);
  const findings = input.findings;

  const hasCritical = hasFindingAtOrAbove(findings, SEVERITY_RANK.critical);
  const hasHigh = hasFindingAtOrAbove(findings, SEVERITY_RANK.high);
  const hasLethalTrifecta = findings.some((f) => f.rule_id === "F1" || f.rule_id === "I13");

  // Pill rules (conservative — RISK wins ties):
  //   - any critical finding OR lethal trifecta OR band=critical → RISK
  //   - any high finding OR band ∈ {moderate, poor} → CAUTION
  //   - else → SAFE
  let pill: AuditVerdictPill;
  if (hasCritical || hasLethalTrifecta || band === "critical") {
    pill = "RISK";
  } else if (hasHigh || band === "moderate" || band === "poor") {
    pill = "CAUTION";
  } else {
    pill = "SAFE";
  }

  const reasons = deriveVerdictReasons(input, { hasLethalTrifecta, hasCritical, hasHigh });
  const worstCase = deriveWorstCase(input, findings);

  return { pill, score: totalScore, band, reasons, worst_case: worstCase };
}

function deriveVerdictReasons(
  input: BuildAuditSummaryInput,
  flags: { hasLethalTrifecta: boolean; hasCritical: boolean; hasHigh: boolean },
): string[] {
  const reasons: string[] = [];
  const findings = input.findings;
  const attackChains = input.attackChains ?? [];

  // Priority cascade — most severe signal wins, capped at 3 reasons.
  if (flags.hasLethalTrifecta) {
    reasons.push(
      "Lethal trifecta detected — capability + exfiltration + untrusted-input present in the same configuration",
    );
  }

  // Critical kill chain (engine rated high/critical exploitability)
  const criticalChain = attackChains.find(
    (c) => c.exploitability_rating === "critical" || c.exploitability_rating === "high",
  );
  if (criticalChain && reasons.length < 3) {
    reasons.push(
      `Multi-step ${criticalChain.kill_chain_id} kill chain (${criticalChain.kill_chain_name}) is exploitable on this server`,
    );
  }

  // Critical findings count
  const critCount = findings.filter((f) => f.severity === "critical").length;
  if (critCount > 0 && reasons.length < 3) {
    reasons.push(
      `${critCount} critical finding${critCount === 1 ? "" : "s"} on this server`,
    );
  }

  // High findings count (only if we still have room and no criticals already used the slot)
  const highCount = findings.filter((f) => f.severity === "high").length;
  if (highCount > 0 && reasons.length < 3 && !flags.hasCritical) {
    reasons.push(
      `${highCount} high-severity finding${highCount === 1 ? "" : "s"} on this server`,
    );
  }

  // Coverage gap (if we have room and the coverage is materially incomplete)
  const coverage = input.score?.analysis_coverage ?? null;
  const skipRatio =
    coverage && coverage.rules_executed + coverage.rules_skipped_no_data > 0
      ? coverage.rules_skipped_no_data /
        (coverage.rules_executed + coverage.rules_skipped_no_data)
      : 0;
  if (skipRatio > 0.3 && reasons.length < 3) {
    reasons.push(
      `${coverage?.rules_skipped_no_data ?? 0} rules could not run for missing inputs (source code, runtime connection, or dependencies)`,
    );
  }

  // Clean baseline — only if no other signals
  if (reasons.length === 0) {
    if (findings.length === 0) {
      reasons.push("No findings on this server with the rules applicable to its profile");
    } else {
      reasons.push(
        `${findings.length} finding${findings.length === 1 ? "" : "s"} present, none rated above medium`,
      );
    }
  }

  return reasons.slice(0, 3);
}

function deriveWorstCase(
  input: BuildAuditSummaryInput,
  findings: Finding[],
): string {
  // Priority 1: top kill chain narrative — already deterministic prose.
  const sortedChains = [...(input.attackChains ?? [])].sort(
    (a, b) => b.exploitability_overall - a.exploitability_overall,
  );
  const topChain = sortedChains[0];
  if (topChain && topChain.narrative.trim().length > 0) {
    return topChain.narrative.trim();
  }

  // Priority 2: top finding's evidence narrative.
  const sortedFindings = [...findings].sort(
    (a, b) => (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0),
  );
  const topFinding = sortedFindings[0];
  if (topFinding && topFinding.evidence.trim().length > 0) {
    // Trim to a single sentence so the worst-case panel stays scannable.
    const oneSentence = firstSentence(topFinding.evidence.trim());
    return oneSentence;
  }

  // Priority 3: honest empty state.
  return "No worst-case scenario has been observed on this server in the latest scan.";
}

function firstSentence(text: string): string {
  // Stop at the first sentence terminator followed by whitespace or end.
  // Conservative — preserves the full text if no sentence boundary found.
  const m = text.match(/^([^.!?]+[.!?])(\s|$)/);
  return m ? m[1].trim() : text.length > 240 ? text.slice(0, 237) + "..." : text;
}

// ─── §2 Testing Depth ───────────────────────────────────────────────────────

function deriveTestingDepth(input: BuildAuditSummaryInput): AuditTestingDepth {
  const coverage = input.score?.analysis_coverage ?? null;

  // categories_tested = category IDs where at least one rule executed.
  // We rely on the deep-dive's already-assembled per-category counts.
  const categoriesTested: string[] = [];
  for (const cat of input.deepDive.categories) {
    const counts = (cat as DeepDiveCategory).counts;
    const tested = counts.rules_passed + counts.rules_with_findings;
    if (tested > 0) categoriesTested.push(cat.id);
  }

  return {
    categories_tested: categoriesTested,
    tests_executed: coverage?.rules_executed ?? 0,
    tests_skipped_no_data: coverage?.rules_skipped_no_data ?? 0,
    inputs_available: {
      code: coverage?.had_source_code ?? false,
      runtime: coverage?.had_connection ?? false,
      deps: coverage?.had_dependencies ?? false,
    },
    coverage_level: mapCoverageBand(input.score?.coverage_band ?? null),
  };
}

export function mapCoverageBand(
  band: "high" | "medium" | "low" | "minimal" | null,
): AuditCoverageLevel {
  if (band === "high") return "HIGH";
  if (band === "medium") return "MEDIUM";
  // low / minimal / null all collapse to LOW — the page renders an
  // explicit "give us source code, we'll go deeper" prompt regardless.
  return "LOW";
}

// ─── §3 Attack Intelligence ─────────────────────────────────────────────────

function deriveAttackIntelligence(input: BuildAuditSummaryInput) {
  const chains = [...(input.attackChains ?? [])].sort(
    (a, b) => b.exploitability_overall - a.exploitability_overall,
  );
  const top = chains.slice(0, 5);

  const scenarios: AuditAttackScenario[] = top.map((chain) => {
    const trio = extractSourcePropagationSink(chain);
    return {
      chain_id: chain.chain_id,
      name: chain.kill_chain_name,
      narrative: chain.narrative,
      source: trio.source,
      propagation: trio.propagation,
      sink: trio.sink,
      outcome: deriveOutcome(chain),
    };
  });

  return { scenarios };
}

/**
 * Pull the source / propagation / sink trio out of a chain's `steps[]`.
 * The attack-graph engine emits `{ ordinal, server_name, role, narrative, ... }`
 * per step. Role values include "source", "propagator", "sink" (deterministic
 * per ADR-006). We render `server_name` as the human-facing label so the
 * scenario tells a story like "GitHub MCP → Vector DB → Slack MCP".
 */
function extractSourcePropagationSink(chain: DeepDiveAttackChain): {
  source: string;
  propagation: string[];
  sink: string;
} {
  const steps = Array.isArray(chain.steps) ? chain.steps : [];
  const labels: string[] = [];
  for (const step of steps) {
    if (!step || typeof step !== "object") continue;
    const s = step as Record<string, unknown>;
    const name =
      typeof s["server_name"] === "string"
        ? (s["server_name"] as string)
        : typeof s["narrative"] === "string"
          ? truncate(s["narrative"] as string, 80)
          : null;
    if (name) labels.push(name);
  }

  if (labels.length === 0) {
    return { source: "(unknown)", propagation: [], sink: "(unknown)" };
  }
  if (labels.length === 1) {
    return { source: labels[0], propagation: [], sink: labels[0] };
  }
  return {
    source: labels[0],
    propagation: labels.slice(1, -1),
    sink: labels[labels.length - 1],
  };
}

/**
 * Outcome for a single attack chain. Conservative — VULNERABLE wins ties.
 *
 * The attack-graph engine's `exploitability_rating` already considers
 * mitigations:
 *   - "critical" / "high" — chain is actively exploitable on this server
 *   - "low"               — engine considered the path but rated it low
 *                           risk (mitigations present or weak preconditions)
 *   - "medium"            — observed configuration with no mitigation signal
 *                           either way → conservative NOT_OBSERVED
 *
 * BLOCKED is reserved for the "low" rating because that's the engine's
 * explicit signal that defenses are present. NOT_OBSERVED is the honest
 * default — the configuration exists but exploitation isn't proven.
 */
export function deriveOutcome(chain: DeepDiveAttackChain): AuditAttackOutcome {
  const rating = chain.exploitability_rating;
  if (rating === "critical" || rating === "high") return "VULNERABLE";
  if (rating === "low") return "BLOCKED";
  return "NOT_OBSERVED";
}

// ─── §4 Risk Summary ────────────────────────────────────────────────────────

function deriveRiskSummary(input: BuildAuditSummaryInput): AuditRiskSummary {
  const categories = input.deepDive.categories.map((cat) => ({
    category_id: cat.id,
    name: cat.title,
    status: deriveCategoryStatus(cat),
  }));
  return { categories };
}

/**
 * Per-category status pill.
 *
 *   SAFE     — 0 findings AND at least one rule actually ran for this category
 *   CAUTION  — at least one finding ≥ medium severity
 *   UNKNOWN  — no rule ran (rules_executed === 0) OR every rule was skipped
 *
 * RISK is intentionally NOT a category-level status — that's the top-line
 * verdict only. Avoiding pill inflation: three SAFE/CAUTION/RISK pills at
 * different scales would dilute the top-line verdict's signal.
 */
export function deriveCategoryStatus(cat: DeepDiveCategory): AuditCategoryStatus {
  const counts = cat.counts;
  // CAUTION wins as soon as a meaningful finding exists. We treat low /
  // informational as not-yet-actionable for the category pill (they show in
  // the rule cards, but don't escalate the category).
  const findings = counts.severity_breakdown;
  if (
    findings.critical > 0 ||
    findings.high > 0 ||
    findings.medium > 0
  ) {
    return "CAUTION";
  }
  // No meaningful findings — was anything tested?
  const tested = counts.rules_passed + counts.rules_with_findings;
  if (tested === 0) return "UNKNOWN";
  return "SAFE";
}

// ─── §5 Gaps ────────────────────────────────────────────────────────────────

function deriveGaps(input: BuildAuditSummaryInput): AuditGap[] {
  const gaps: AuditGap[] = [];
  for (const cat of input.deepDive.categories) {
    for (const sub of cat.sub_categories) {
      for (const rule of sub.rules) {
        if (rule.status !== "skipped") continue;
        // is_canonical guard so we don't double-count a rule appearing in
        // multiple sub-categories (Phase 1.3 invariant).
        const canonical =
          (rule as DeepDiveRule & { is_canonical?: boolean }).is_canonical !== false;
        if (!canonical) continue;

        // The skip_reason field is set by deep-dive's deriveSkipReason and
        // rides via passthrough. Read it defensively — we can still emit a
        // gap entry without it (with empty missing_inputs) when the
        // structured reason was not derived.
        const skipReason = (rule as DeepDiveRule & {
          skip_reason?: { missing_inputs: string[] };
        }).skip_reason;
        gaps.push({
          rule_id: rule.rule_id,
          name: rule.name,
          missing_inputs: skipReason?.missing_inputs ? [...skipReason.missing_inputs] : [],
          impact: severityToImpact(rule.severity),
        });
      }
    }
  }
  return gaps;
}

function severityToImpact(sev: Severity): AuditImpact {
  if (sev === "critical" || sev === "high") return "HIGH";
  if (sev === "medium") return "MEDIUM";
  return "LOW";
}

// ─── §6 Recommendation ──────────────────────────────────────────────────────

/**
 * Decision tree — auditable, ordered, single-pass. Conservative bias:
 * when two rules could fire, the more restrictive wins (NO > CONDITIONAL > YES).
 *
 *   1. Any chain with VULNERABLE outcome AND severity=critical → NO
 *      rationale: "active critical exploit chain observed"
 *   2. Lethal trifecta (F1 or I13) finding present → NO
 *      rationale: "lethal trifecta — capability + exfil + untrusted input"
 *   3. score < 40 → NO
 *      rationale: "score in critical band"
 *   4. score < 60 → CONDITIONAL with top 3 high-severity findings as conditions
 *   5. Any chain with VULNERABLE outcome (non-critical) → CONDITIONAL
 *   6. coverage_level === "LOW" → CONDITIONAL with conditions filtered by
 *      inputs_available (e.g. "re-scan with source code access")
 *   7. confidence.level === "LOW" → CONDITIONAL
 *   8. else → YES
 *
 * Thresholds 40/60 align with existing scoreBand boundaries — no new magic
 * numbers introduced. Every decision emits a `rationale` line so the page
 * shows WHY, not just WHAT.
 */
export function deriveRecommendation(
  input: BuildAuditSummaryInput,
  attackIntel: { scenarios: AuditAttackScenario[] },
  confidence: AuditConfidence,
): AuditRecommendation {
  const findings = input.findings;
  const score = input.score?.total_score ?? 0;
  const rationale: string[] = [];
  const conditions: string[] = [];

  const criticalVulnerable = attackIntel.scenarios.find(
    (s) => s.outcome === "VULNERABLE" && isCriticalSeverityLabel(s.name),
  );
  const anyVulnerable = attackIntel.scenarios.find((s) => s.outcome === "VULNERABLE");
  const lethalTrifecta = findings.find((f) => f.rule_id === "F1" || f.rule_id === "I13");

  let decision: AuditRecommendationDecision = "YES";

  // Rule 1 — active critical exploit chain
  if (criticalVulnerable) {
    decision = mostRestrictive(decision, "NO");
    rationale.push(
      `active critical exploit chain observed (${criticalVulnerable.chain_id} — ${criticalVulnerable.name})`,
    );
  }

  // Rule 2 — lethal trifecta
  if (lethalTrifecta) {
    decision = mostRestrictive(decision, "NO");
    rationale.push("lethal trifecta detected — capability + exfiltration + untrusted-input");
  }

  // Rule 3 — critical band
  if (score < 40) {
    decision = mostRestrictive(decision, "NO");
    rationale.push(`score in critical band (${score} < 40)`);
  }

  // Rule 4 — score below 60
  if (score < 60) {
    decision = mostRestrictive(decision, "CONDITIONAL");
    rationale.push(`score below moderate band (${score} < 60)`);
    // Top 3 high+critical findings as conditions
    const top = [...findings]
      .filter((f) => f.severity === "critical" || f.severity === "high")
      .slice(0, 3);
    for (const f of top) {
      conditions.push(`Resolve ${f.severity} finding ${f.rule_id}: ${truncate(f.evidence, 120)}`);
    }
  }

  // Rule 5 — non-critical VULNERABLE chain
  if (!criticalVulnerable && anyVulnerable) {
    decision = mostRestrictive(decision, "CONDITIONAL");
    rationale.push(
      `kill chain ${anyVulnerable.chain_id} (${anyVulnerable.name}) is exploitable on this server`,
    );
    conditions.push(`Mitigate ${anyVulnerable.chain_id} before production deployment`);
  }

  // Rule 6 — coverage LOW
  if (confidence.level !== "HIGH") {
    const coverage = input.score?.analysis_coverage;
    if (mapCoverageBand(input.score?.coverage_band ?? null) === "LOW") {
      decision = mostRestrictive(decision, "CONDITIONAL");
      rationale.push("coverage level LOW — significant attack surface unanalysed");
      // Filter conditions by what we actually CAN improve
      if (coverage && !coverage.had_source_code) {
        conditions.push("Re-scan with source code access (raises code analysis coverage)");
      }
      if (coverage && !coverage.had_connection) {
        conditions.push("Re-scan with a live MCP connection (enables runtime checks)");
      }
      if (coverage && !coverage.had_dependencies) {
        conditions.push("Re-scan with package manifest (enables dependency CVE checks)");
      }
    }
  }

  // Rule 7 — confidence LOW (orthogonal to coverage band)
  if (confidence.level === "LOW") {
    decision = mostRestrictive(decision, "CONDITIONAL");
    rationale.push("verdict confidence LOW — re-scan with more inputs before relying on this score");
  }

  // Rule 8 — default YES
  if (decision === "YES" && rationale.length === 0) {
    rationale.push("Score in good band, no critical or high-severity findings, no exploitable kill chain");
  }

  return {
    use_in_production: decision,
    conditions,
    rationale,
    disclaimer:
      "Decision derived from automated analysis at scan time. Review the rationale and underlying evidence chains before production deployment. No score replaces human judgement.",
  };
}

/** "NO" beats "CONDITIONAL" beats "YES". */
function mostRestrictive(
  a: AuditRecommendationDecision,
  b: AuditRecommendationDecision,
): AuditRecommendationDecision {
  const rank: Record<AuditRecommendationDecision, number> = { NO: 3, CONDITIONAL: 2, YES: 1 };
  return rank[a] >= rank[b] ? a : b;
}

/**
 * Quick heuristic for "this kill chain is critical" — used by the
 * recommendation engine to decide between rule 1 (NO) and rule 5
 * (CONDITIONAL). Today the kill_chain_name itself encodes the rating
 * (e.g. "Critical: Cross-server injection"); when the engine adds a
 * structured severity field on chains we should switch to that.
 */
function isCriticalSeverityLabel(name: string): boolean {
  return /\bcritical\b/i.test(name);
}

// ─── §7 Confidence ──────────────────────────────────────────────────────────

export function deriveConfidence(
  input: BuildAuditSummaryInput,
  testingDepth: AuditTestingDepth,
): AuditConfidence {
  const coverage = input.score?.analysis_coverage ?? null;
  const factors: string[] = [];

  // Skip ratio — fraction of applicable rules that couldn't run for missing inputs.
  const totalApplicable =
    (coverage?.rules_executed ?? 0) + (coverage?.rules_skipped_no_data ?? 0);
  const skipRatio = totalApplicable > 0
    ? (coverage?.rules_skipped_no_data ?? 0) / totalApplicable
    : 0;

  // E2E chain preservation — every persisted finding must carry an evidence_chain
  // for the verdict to be regulator-grade. One missing chain demotes us.
  const chainsPreserved = input.findings.every((f) => f.evidence_chain != null);

  let level: AuditConfidenceLevel;
  if (
    testingDepth.coverage_level === "HIGH" &&
    chainsPreserved &&
    skipRatio < 0.1
  ) {
    level = "HIGH";
    factors.push("HIGH coverage band reported by analyzer");
    factors.push("every finding carries an evidence chain");
    factors.push(`only ${(skipRatio * 100).toFixed(0)}% of applicable rules skipped`);
  } else if (testingDepth.coverage_level === "LOW" || skipRatio > 0.5) {
    level = "LOW";
    if (testingDepth.coverage_level === "LOW") {
      factors.push("LOW coverage band — large parts of the surface unanalysed");
    }
    if (skipRatio > 0.5) {
      factors.push(`${(skipRatio * 100).toFixed(0)}% of applicable rules could not run`);
    }
    if (!chainsPreserved) {
      factors.push("at least one finding lacks an evidence chain");
    }
  } else {
    level = "MEDIUM";
    factors.push(`coverage band: ${testingDepth.coverage_level}`);
    factors.push(`${(skipRatio * 100).toFixed(0)}% of applicable rules skipped`);
    if (!chainsPreserved) {
      factors.push("at least one finding lacks an evidence chain");
    }
  }

  return { level, factors };
}

// ─── §8 Evidence Trust ──────────────────────────────────────────────────────

function deriveEvidenceTrust(input: BuildAuditSummaryInput): AuditEvidenceTrust {
  // Every finding produced by the pipeline goes through the analyzer's
  // EvidenceChainBuilder and is persisted with `evidence_chain` JSONB
  // populated. A finding without a chain is a bug in the rule.
  const e2e = input.findings.length === 0
    ? true
    : input.findings.every((f) => f.evidence_chain != null);
  return {
    runtime_analysis: true,
    e2e_chain_preserved: e2e,
    receipt_url_pattern: "/api/v1/findings/:id/receipt",
  };
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function truncate(text: string, n: number): string {
  if (text.length <= n) return text;
  return text.slice(0, n - 1).trimEnd() + "…";
}
