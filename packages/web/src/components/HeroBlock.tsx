/**
 * HeroBlock — page-opening "What you should know" panel.
 *
 * Replaces the breadcrumb-only top of the Deep Dive page (the breadcrumb
 * stays one row above this; the hero is the FIRST piece of content). Lays
 * out two halves on desktop, stacks on mobile:
 *
 *   Left:  server name (Instrument Serif), coverage line, narrative
 *          bullets ("What you should know" — buildAutoNarrative output).
 *   Right: severity proportional bar with counts.
 *
 * Server component — pure SSR. Bullets are built deterministically from
 * the response (no LLM, ADR-006). Empty bullet list → no narrative panel,
 * but the server name + coverage line still render so the page never
 * looks broken when only sparse data is on file.
 *
 * Visual language: tokens only — `--text`, `--text-2`, `--text-3`,
 * `--surface`, `--surface-2`, `--border`, `--font-display`,
 * `--font-mono`, `--sev-${severity}`.
 */

import React from "react";
import type {
  DeepDiveAttackChain,
  DeepDiveCategory,
  DeepDiveCoverageSummary,
} from "@/lib/deep-dive";
import { buildAutoNarrative } from "@/lib/auto-narrative";

interface HeroBlockProps {
  serverName: string;
  coverage: DeepDiveCoverageSummary | undefined;
  categories: ReadonlyArray<DeepDiveCategory> | undefined;
  attackChains: ReadonlyArray<DeepDiveAttackChain> | undefined;
}

const SEV_ORDER: Array<{
  key: keyof DeepDiveCoverageSummary["severity_breakdown"];
  label: string;
}> = [
  { key: "critical", label: "Critical" },
  { key: "high", label: "High" },
  { key: "medium", label: "Medium" },
  { key: "low", label: "Low" },
  { key: "informational", label: "Info" },
];

const COVERAGE_BAND_COPY: Record<string, string> = {
  high: "high coverage",
  medium: "medium coverage",
  low: "low coverage",
  minimal: "minimal coverage",
};

const TONE_GLYPH: Record<string, string> = {
  critical: "▲",
  high: "▲",
  info: "·",
  good: "✓",
};

export default function HeroBlock({
  serverName,
  coverage,
  categories,
  attackChains,
}: HeroBlockProps) {
  const bullets = buildAutoNarrative({
    coverage,
    categories,
    attackChains,
  });

  // Coverage line: "142 of 164 rules executed · high coverage" — null-safe.
  // Defensive: total_rules and rules_executed may be missing on older
  // api responses; fall back to honest copy rather than crashing.
  const totalRules = Number(coverage?.total_rules) || 0;
  const rulesExecuted = Number(coverage?.rules_executed) || 0;
  const coverageLine =
    coverage && totalRules > 0
      ? `${rulesExecuted} of ${totalRules} rules executed${
          coverage.coverage_band
            ? ` · ${COVERAGE_BAND_COPY[coverage.coverage_band] ?? coverage.coverage_band + " coverage"}`
            : ""
        }`
      : "scan coverage not yet on file";

  // Severity bar segments — only render the bar if there's at least one
  // finding AND severity_breakdown is on the response. Otherwise the
  // right column shows a "no findings" badge.
  const totalFindings = Number(coverage?.total_findings) || 0;
  const breakdown =
    coverage &&
    coverage.severity_breakdown &&
    typeof coverage.severity_breakdown === "object"
      ? coverage.severity_breakdown
      : null;
  const sevBars =
    breakdown && totalFindings > 0
      ? SEV_ORDER.map(({ key, label }) => {
          const count = Number(breakdown[key]) || 0;
          const pct = totalFindings > 0 ? (count / totalFindings) * 100 : 0;
          return { key, label, count, pct };
        }).filter((s) => s.count > 0)
      : [];

  return (
    <section className="dd-hero2" aria-labelledby="dd-hero2-name">
      <div className="dd-hero2-left">
        <h1 id="dd-hero2-name" className="dd-hero2-name">
          {serverName}
        </h1>
        <p className="dd-hero2-coverage" aria-label="Scan coverage">
          {coverageLine}
        </p>

        {bullets.length > 0 && (
          <div
            className="dd-hero2-narrative"
            aria-label="What you should know"
          >
            <h2 className="dd-hero2-narrative-title">What you should know</h2>
            <ul className="dd-hero2-bullets">
              {bullets.map((b) => (
                <li
                  key={b.id}
                  className="dd-hero2-bullet"
                  data-tone={b.tone}
                >
                  <span
                    className={`dd-hero2-bullet-glyph dd-hero2-bullet-${b.tone}`}
                    aria-hidden="true"
                  >
                    {TONE_GLYPH[b.tone] ?? "·"}
                  </span>
                  <span className="dd-hero2-bullet-text">{b.text}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>

      <aside
        className="dd-hero2-right"
        aria-label="Severity breakdown"
      >
        {sevBars.length > 0 ? (
          <>
            <div className="dd-hero2-sev-total">
              <span className="dd-hero2-sev-total-num">{totalFindings}</span>
              <span className="dd-hero2-sev-total-label">
                {totalFindings === 1 ? "finding" : "findings"}
              </span>
            </div>
            <ul className="dd-hero2-sev-list">
              {sevBars.map(({ key, label, count, pct }) => (
                <li
                  key={key}
                  className="dd-hero2-sev-row"
                  data-sev={key}
                >
                  <span className="dd-hero2-sev-label">{label}</span>
                  <span className="dd-hero2-sev-count">{count}</span>
                  <span
                    className="dd-hero2-sev-bar-track"
                    aria-hidden="true"
                  >
                    <span
                      className="dd-hero2-sev-bar-fill"
                      style={{
                        width: `${pct.toFixed(1)}%`,
                        background: `var(--sev-${key === "informational" ? "info" : key})`,
                      }}
                    />
                  </span>
                </li>
              ))}
            </ul>
          </>
        ) : (
          <div className="dd-hero2-clean">
            <span className="dd-hero2-clean-glyph" aria-hidden="true">
              ✓
            </span>
            <span className="dd-hero2-clean-text">No findings on file</span>
          </div>
        )}
      </aside>
    </section>
  );
}
