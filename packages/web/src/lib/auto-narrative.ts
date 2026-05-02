/**
 * AutoNarrative — deterministic templated bullets for the Deep Dive hero.
 *
 * Pure function: same inputs → same bullets, byte-equal. ADR-006 compliant
 * (no LLM, no randomness). The frontend renders these as the "What you
 * should know" stack at the top of the page so a regulator's first read
 * lands on prose, not a numbers grid.
 *
 * The function returns 0–5 ordered bullets. Each bullet is a stable
 * one-line English sentence. Empty array means "the data on file does
 * not support any of the templated narratives" — the page renders nothing
 * (honest gap, no synthetic placeholder).
 *
 * Bullet ordering (priority, highest first):
 *   1. lethal trifecta / score-cap (when the inputs hint at it)
 *   2. multi-step kill chain (the headline attack story)
 *   3. critical / high finding count (concrete severity numbers)
 *   4. coverage gap (what we couldn't test)
 *   5. clean-posture celebration (when truly clean OR a category is clean)
 *
 * The shipping bullets stop at 5 to keep the hero scannable. Lower-
 * priority templates that don't fire are silently dropped.
 */

import type {
  DeepDiveAttackChain,
  DeepDiveCategory,
  DeepDiveCoverageSummary,
} from "./deep-dive";

export interface NarrativeBullet {
  /** Stable, copy-pasteable English sentence. Ends with a period. */
  text: string;
  /** Tone hint for visual styling — drives bullet glyph + color. */
  tone: "critical" | "high" | "info" | "good";
  /** Stable id so the page can key the React list and so tests can
   *  assert which template fired. */
  id:
    | "lethal-trifecta"
    | "kill-chain"
    | "critical-findings"
    | "high-findings"
    | "coverage-gap"
    | "clean-category"
    | "clean-server";
}

export interface AutoNarrativeInput {
  coverage: DeepDiveCoverageSummary | undefined;
  categories: ReadonlyArray<DeepDiveCategory> | undefined;
  attackChains: ReadonlyArray<DeepDiveAttackChain> | undefined;
}

/** Cap shipped bullets so the hero stays scannable. */
const MAX_BULLETS = 5;

/** Detect the lethal-trifecta hint from F1 / I13 fingerprints in the
 *  category set. The api emits per-category counts but not the rule-id of
 *  the offender; we inspect category metadata for the canonical
 *  "lethal-trifecta" / "cross-server-trifecta" sub-categories or any
 *  category whose summary mentions the trifecta. Conservative — we only
 *  fire when the data clearly supports it.
 *
 *  Defensive: every field is checked at runtime because production data
 *  may be served by an older api that emits slightly different shapes
 *  (missing counts, missing sub_categories, etc.). The page must never
 *  crash on a partial response. */
function looksLikeLethalTrifecta(
  categories: ReadonlyArray<DeepDiveCategory>,
): boolean {
  for (const cat of categories) {
    if (!cat || typeof cat !== "object") continue;
    if (
      cat.id === "lethal-trifecta" &&
      cat.counts &&
      typeof cat.counts.rules_with_findings === "number" &&
      cat.counts.rules_with_findings > 0
    ) {
      return true;
    }
    const subs = Array.isArray(cat.sub_categories) ? cat.sub_categories : [];
    for (const sub of subs) {
      if (!sub || typeof sub !== "object") continue;
      if (
        (sub.id === "lethal-trifecta" || sub.id === "cross-config-trifecta") &&
        sub.counts &&
        typeof sub.counts.rules_with_findings === "number" &&
        sub.counts.rules_with_findings > 0
      ) {
        return true;
      }
    }
  }
  return false;
}

/** Pick the highest-exploitability chain. Stable tie-break: lexicographic
 *  on `chain_id` so the same input always yields the same headline.
 *  Defensive: skips entries with non-numeric exploitability or missing
 *  required strings. */
function worstChain(
  chains: ReadonlyArray<DeepDiveAttackChain>,
): DeepDiveAttackChain | null {
  const valid = chains.filter(
    (c) =>
      c &&
      typeof c.exploitability_overall === "number" &&
      typeof c.chain_id === "string" &&
      typeof c.kill_chain_id === "string" &&
      typeof c.kill_chain_name === "string",
  );
  if (valid.length === 0) return null;
  let best = valid[0]!;
  for (const c of valid) {
    if (
      c.exploitability_overall > best.exploitability_overall ||
      (c.exploitability_overall === best.exploitability_overall &&
        c.chain_id < best.chain_id)
    ) {
      best = c;
    }
  }
  return best;
}

function pluralise(n: number, singular: string, plural?: string): string {
  if (n === 1) return `${n} ${singular}`;
  return `${n} ${plural ?? singular + "s"}`;
}

/** Build the deterministic bullet list. */
export function buildAutoNarrative(input: AutoNarrativeInput): NarrativeBullet[] {
  const out: NarrativeBullet[] = [];
  const cov = input.coverage;
  const cats = input.categories ?? [];
  const chains = input.attackChains ?? [];

  // (1) Lethal trifecta — score cap moment.
  if (looksLikeLethalTrifecta(cats)) {
    out.push({
      id: "lethal-trifecta",
      tone: "critical",
      text: "Lethal trifecta detected — total score is capped at 40 regardless of other findings.",
    });
  }

  // (2) Headline kill chain.
  const chain = worstChain(chains);
  if (chain) {
    const stepCount = Array.isArray(chain.steps) ? chain.steps.length : 0;
    const tone: NarrativeBullet["tone"] =
      chain.exploitability_rating === "critical" ? "critical" : "high";
    const stepsPart =
      stepCount > 0
        ? ` in ${pluralise(stepCount, "step")} via ${chain.kill_chain_id}`
        : ` via ${chain.kill_chain_id}`;
    out.push({
      id: "kill-chain",
      tone,
      text: `An attacker reaches ${chain.kill_chain_name.toLowerCase()}${stepsPart}.`,
    });
  }

  // (3) Critical / high finding density. Defensive against missing
  // severity_breakdown — older api responses may omit it.
  if (cov && cov.severity_breakdown && typeof cov.severity_breakdown === "object") {
    const c = Number(cov.severity_breakdown.critical) || 0;
    const h = Number(cov.severity_breakdown.high) || 0;
    const rwf = Number(cov.rules_with_findings) || 0;
    if (c > 0) {
      out.push({
        id: "critical-findings",
        tone: "critical",
        text: `${pluralise(c, "critical finding")}${
          h > 0 ? ` and ${pluralise(h, "high-severity finding")}` : ""
        } across ${pluralise(rwf, "rule")}.`,
      });
    } else if (h > 0) {
      out.push({
        id: "high-findings",
        tone: "high",
        text: `${pluralise(h, "high-severity finding")} across ${pluralise(
          rwf,
          "rule",
        )} — no criticals on file.`,
      });
    }
  }

  // (4) Coverage gap — what we couldn't test.
  if (cov && cov.rules_skipped_no_data > 0) {
    out.push({
      id: "coverage-gap",
      tone: "info",
      text: `${pluralise(
        cov.rules_skipped_no_data,
        "rule",
      )} could not be tested for this scan — see the coverage ledger below.`,
    });
  }

  // (5a) Clean-server celebration when truly clean (no findings, coverage
  //      band high, no skipped rules).
  if (
    cov &&
    cov.total_findings === 0 &&
    cov.rules_skipped_no_data === 0 &&
    cov.coverage_band === "high"
  ) {
    out.push({
      id: "clean-server",
      tone: "good",
      text: `Clean — ${pluralise(
        cov.rules_executed,
        "rule",
      )} executed, no findings.`,
    });
  } else {
    // (5b) Otherwise, celebrate ONE strong-posture category to balance
    //      the bad news. Pick the largest tested category with zero
    //      findings; tie-break by id for determinism.
    const cleanCat = cats
      .filter(
        (c) =>
          c &&
          c.counts &&
          c.counts.rules_with_findings === 0 &&
          (c.counts.rules_passed ?? 0) >= 3 &&
          c.counts.rules_skipped === 0,
      )
      .sort((a, b) => {
        const ap = a.counts?.rules_passed ?? 0;
        const bp = b.counts?.rules_passed ?? 0;
        if (ap !== bp) return bp - ap;
        return (a.id ?? "").localeCompare(b.id ?? "");
      })[0];
    if (cleanCat) {
      const passed = cleanCat.counts?.rules_passed ?? 0;
      out.push({
        id: "clean-category",
        tone: "good",
        text: `Strong posture in ${cleanCat.title ?? cleanCat.id} — 0 findings across ${pluralise(
          passed,
          "rule",
        )}.`,
      });
    }
  }

  return out.slice(0, MAX_BULLETS);
}

/** Headline verdict — single-sentence summary used by the sticky
 *  VerdictBar. Always returns one string (never empty) so the bar always
 *  has something to say. Highest-priority signal wins; otherwise the
 *  honest-pessimism fallback fires. */
export function buildVerdictHeadline(input: AutoNarrativeInput): {
  text: string;
  tone: NarrativeBullet["tone"];
} {
  const cov = input.coverage;
  const chains = input.attackChains ?? [];
  const cats = input.categories ?? [];

  if (looksLikeLethalTrifecta(cats)) {
    return {
      text: "Critical — lethal trifecta capping this server's score at 40.",
      tone: "critical",
    };
  }
  const chain = worstChain(chains);
  if (chain && chain.exploitability_rating === "critical") {
    return {
      text: `Critical — ${chain.kill_chain_id} ${chain.kill_chain_name.toLowerCase()} is reachable.`,
      tone: "critical",
    };
  }
  if (cov && cov.severity_breakdown && typeof cov.severity_breakdown === "object") {
    const c = Number(cov.severity_breakdown.critical) || 0;
    const h = Number(cov.severity_breakdown.high) || 0;
    if (c > 0) {
      return {
        text: `Critical — ${pluralise(c, "critical finding")}${
          h > 0 ? ` and ${pluralise(h, "high-severity finding")}` : ""
        }.`,
        tone: "critical",
      };
    }
    if (chain) {
      return {
        text: `${
          chain.exploitability_rating[0]!.toUpperCase() +
          chain.exploitability_rating.slice(1)
        } risk — ${chain.kill_chain_id} kill chain present.`,
        tone: chain.exploitability_rating === "high" ? "high" : "info",
      };
    }
    if (h > 0) {
      return {
        text: `High risk — ${pluralise(h, "high-severity finding")}.`,
        tone: "high",
      };
    }
    if (cov.total_findings > 0) {
      return {
        text: `${pluralise(cov.total_findings, "finding")} on file — no criticals or highs.`,
        tone: "info",
      };
    }
    if (cov.coverage_band === "high" && cov.rules_executed > 0) {
      return {
        text: `Clean — ${pluralise(cov.rules_executed, "rule")} executed, no findings.`,
        tone: "good",
      };
    }
  }
  // Honest-pessimism fallback — when we have no signal at all, say so
  // rather than inventing a verdict.
  return {
    text: "Awaiting scan data for this server.",
    tone: "info",
  };
}
