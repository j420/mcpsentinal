/**
 * CoverageLedger — first-class section listing every rule we couldn't
 * test, grouped by structured reason.
 *
 * The data source is each rule's `skip_reason` (api `deriveSkipReason`).
 * Rules are bucketed by the SET of `missing_inputs` so all rules waiting
 * on the same input land in one bucket. Each bucket header names the
 * reason and the action ("give us source code, we'll test these N
 * rules"); the body lists the rule ids + names compactly.
 *
 * Renders nothing when no rules are skipped. Server component, no hooks.
 *
 * Why a "ledger" frame rather than a chart:
 *   - Tabular monospace reads like a print manifest — visual honesty,
 *     not marketing.
 *   - Auditors copy rule lists out of the page for their own
 *     spreadsheets; tables are diff-friendly.
 *   - The structured reason makes "uploaded source code → testable
 *     coverage" obvious without prose.
 */

import React from "react";
import type {
  DeepDiveCategory,
  DeepDiveCoverageSummary,
  DeepDiveRule,
  DeepDiveSkipInput,
} from "@/lib/deep-dive";

interface CoverageLedgerProps {
  coverage: DeepDiveCoverageSummary | undefined;
  categories: ReadonlyArray<DeepDiveCategory> | undefined;
}

interface SkipBucket {
  /** Stable key — sorted missing-input list joined with "+". */
  key: string;
  missing_inputs: DeepDiveSkipInput[];
  summary: string;
  rules: Array<{ rule_id: string; name: string }>;
}

const REMEDY_FOR_INPUT: Record<DeepDiveSkipInput, string> = {
  source_code: "give us a fetchable source URL",
  connection: "expose a reachable MCP endpoint",
  dependencies: "publish a package manifest (npm/pypi)",
};

function formatBucketAction(missing: DeepDiveSkipInput[]): string {
  // One-line "what would unblock this bucket" — mirrors the api's
  // `skipSummary` priorities. Keeps single-input buckets crisp; multi-
  // input buckets enumerate.
  if (missing.length === 1) {
    return REMEDY_FOR_INPUT[missing[0]!];
  }
  return missing.map((m) => REMEDY_FOR_INPUT[m]).join("; ");
}

export default function CoverageLedger({
  coverage,
  categories,
}: CoverageLedgerProps) {
  if (!categories || categories.length === 0) return null;

  // Walk every rule once, dropping the skipped ones into the right bucket.
  const buckets = new Map<string, SkipBucket>();
  const allRules: DeepDiveRule[] = [];
  for (const cat of categories) {
    for (const sub of cat.sub_categories) {
      for (const rule of sub.rules) {
        if (rule.status !== "skipped") continue;
        // Avoid double-counting a rule when it appears in multiple
        // sub-categories via cross-referencing.
        if (allRules.some((r) => r.rule_id === rule.rule_id)) continue;
        allRules.push(rule);

        const reason = rule.skip_reason;
        if (!reason) continue;
        const sortedMissing = [...reason.missing_inputs].sort();
        const key = sortedMissing.join("+");
        const bucket =
          buckets.get(key) ??
          (buckets.set(key, {
            key,
            missing_inputs: sortedMissing,
            summary: reason.summary,
            rules: [],
          }),
          buckets.get(key)!);
        bucket.rules.push({ rule_id: rule.rule_id, name: rule.name });
      }
    }
  }

  if (buckets.size === 0) return null;

  // Stable bucket ordering: by number of rules desc, then by key asc.
  const orderedBuckets = Array.from(buckets.values()).sort((a, b) => {
    if (b.rules.length !== a.rules.length) {
      return b.rules.length - a.rules.length;
    }
    return a.key.localeCompare(b.key);
  });

  const totalSkipped = allRules.length;

  // Aggregate "if you give us source code, we'd test N more rules"
  // headline number. Computed from buckets that include source_code.
  const wouldTestIfSource = orderedBuckets
    .filter((b) => b.missing_inputs.includes("source_code"))
    .reduce((acc, b) => acc + b.rules.length, 0);

  return (
    <section className="cov-ledger" aria-labelledby="cov-ledger-title">
      <header className="cov-ledger-head">
        <h2 id="cov-ledger-title" className="cov-ledger-title">
          Coverage ledger
          <span className="cov-ledger-count">
            {totalSkipped} rule{totalSkipped === 1 ? "" : "s"} not run
          </span>
        </h2>
        <p className="cov-ledger-sub">
          Every rule we could not test on this scan, with the structured
          reason. Honest gaps over invented passes.
          {wouldTestIfSource > 0 && coverage?.had_source_code === false && (
            <>
              {" "}
              <strong className="cov-ledger-cta">
                {wouldTestIfSource} of these become testable if we get
                source code for this server.
              </strong>
            </>
          )}
        </p>
      </header>

      <div className="cov-ledger-buckets">
        {orderedBuckets.map((bucket) => (
          <article
            key={bucket.key}
            className="cov-bucket"
            aria-labelledby={`cov-bucket-${bucket.key}`}
          >
            <header className="cov-bucket-head">
              <h3
                id={`cov-bucket-${bucket.key}`}
                className="cov-bucket-title"
              >
                {bucket.summary}
              </h3>
              <span className="cov-bucket-count">
                {bucket.rules.length} rule
                {bucket.rules.length === 1 ? "" : "s"}
              </span>
            </header>
            <p className="cov-bucket-action">
              <span className="cov-bucket-action-label">To unblock:</span>{" "}
              {formatBucketAction(bucket.missing_inputs)}.
            </p>
            <ul className="cov-bucket-rules">
              {bucket.rules.map((r) => (
                <li key={r.rule_id} className="cov-bucket-rule">
                  <a
                    className="cov-bucket-rule-link"
                    href={`#rule-${r.rule_id}`}
                    title={r.name}
                  >
                    <code className="cov-bucket-rule-id">{r.rule_id}</code>
                    <span className="cov-bucket-rule-name">{r.name}</span>
                  </a>
                </li>
              ))}
            </ul>
          </article>
        ))}
      </div>
    </section>
  );
}
