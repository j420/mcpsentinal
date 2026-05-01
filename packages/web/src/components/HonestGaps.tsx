/**
 * HonestGaps — what we did NOT analyse, with reasons.
 *
 * Positioned above FooterAttestationBar on the server detail page.
 * The CISO frame: an auditor-grade product leads with its gaps;
 * only a marketing page hides them.
 *
 * Renders even when analysis_coverage is null — static rows still appear,
 * dynamic rows degrade to a "coverage data unavailable" note. Resilience
 * over perfection: this component never throws, never blocks the page.
 *
 * Coverage band derivation matches packages/analyzer/src/engine.ts:
 *   - high:    coverage_ratio >= 0.80 AND had_source_code AND had_connection
 *   - medium:  coverage_ratio >= 0.60
 *   - low:     coverage_ratio >= 0.30
 *   - minimal: otherwise
 *
 * Visual tokens use the same band colours the score hero uses
 * (--good / --moderate / --poor / --critical), keyed off the band rather
 * than the score so a "high coverage / low score" server still shows green
 * confidence here.
 */

import React from "react";

// ── Types (intentionally aligned to scorer.AnalysisCoverageInput minus
// confidence_band — we derive that locally so the component stays usable
// even when the API does not yet expose the band field) ─────────────────
export interface HonestGapsCoverage {
  had_source_code: boolean;
  had_connection: boolean;
  had_dependencies: boolean;
  coverage_ratio: number;
  techniques_run: string[];
  rules_executed: number;
  rules_skipped_no_data: number;
}

interface Props {
  analysis_coverage: HonestGapsCoverage | null;
  // Currently unused in visible output but kept on the contract so the
  // panel can tighten to "X findings produced from Y rules" in a follow-up
  // without a prop-shape change.
  findingsCount: number;
}

type Band = "high" | "medium" | "low" | "minimal";

// ── Helpers ─────────────────────────────────────────────────────────────

function deriveBand(c: HonestGapsCoverage): Band {
  // Mirror engine.ts derivation. Keep this function pure for testability.
  if (c.coverage_ratio >= 0.80 && c.had_source_code && c.had_connection) return "high";
  if (c.coverage_ratio >= 0.60) return "medium";
  if (c.coverage_ratio >= 0.30) return "low";
  return "minimal";
}

const BAND_LABEL: Record<Band, string> = {
  high: "HIGH coverage",
  medium: "MEDIUM coverage",
  low: "LOW coverage",
  minimal: "MINIMAL coverage",
};

// Map band → CSS var token. Token list dictated by the brief.
const BAND_TOKEN: Record<Band, string> = {
  high: "good",
  medium: "moderate",
  low: "poor",
  minimal: "critical",
};

// ── Row primitive ───────────────────────────────────────────────────────

function StatusRow({
  label,
  ok,
  okText,
  notOkText,
}: {
  label: string;
  ok: boolean | null;
  okText: string;
  notOkText: string;
}) {
  const present = ok === true;
  const cls = ok === null ? "hg-row-unknown" : present ? "hg-row-ok" : "hg-row-miss";
  const mark = ok === null ? "—" : present ? "✓" : "×";
  const text = ok === null ? "coverage data unavailable" : present ? okText : notOkText;
  return (
    <li className={`hg-row ${cls}`}>
      <span className="hg-mark" aria-hidden="true">{mark}</span>
      <span className="hg-row-label">{label}</span>
      <span className="hg-row-text">{text}</span>
    </li>
  );
}

// ── Component ───────────────────────────────────────────────────────────

export default function HonestGaps({ analysis_coverage }: Props) {
  // ── Derive band + chip colour. When coverage is null, chip is muted. ─
  const c = analysis_coverage;
  const band: Band | null = c ? deriveBand(c) : null;
  const token = band ? BAND_TOKEN[band] : null;

  // ── Dynamic ratios. Three values:
  //     - actual count (string) when coverage present
  //     - "—" when not.
  const rulesExec = c?.rules_executed ?? null;
  const rulesSkip = c?.rules_skipped_no_data ?? null;
  const rulesTotal =
    rulesExec != null && rulesSkip != null ? rulesExec + rulesSkip : null;

  return (
    <section
      id="honest-gaps"
      className="hg-card"
      aria-labelledby="hg-title"
    >
      {/* ── Card head: title + coverage band chip ───────────────────── */}
      <header className="hg-head">
        <div className="hg-head-text">
          <span className="hg-eyebrow">Coverage transparency</span>
          <h2 id="hg-title" className="hg-title">
            What we did not analyse — and why
          </h2>
          <p className="hg-tagline">
            An auditor-grade scan reports its gaps. Every line below is a
            limitation of this scan, not a property of the server.
          </p>
        </div>

        <div
          className={`hg-band-chip${token ? ` hg-band-${token}` : " hg-band-unknown"}`}
          aria-label={band ? BAND_LABEL[band] : "Coverage data unavailable"}
        >
          <span className="hg-band-key">band</span>
          <span className="hg-band-value">
            {band ? BAND_LABEL[band] : "—"}
          </span>
        </div>
      </header>

      {/* ── Rows ────────────────────────────────────────────────────── */}
      <ul className="hg-list">
        <StatusRow
          label="Source code"
          ok={c ? c.had_source_code : null}
          okText="fetched and analysed (AST taint, secret scan, dependency parse)"
          notOkText="not fetched (private repo, missing identifier, or fetch error)"
        />
        <StatusRow
          label="Live connection"
          ok={c ? c.had_connection : null}
          okText="initialize + tools/list succeeded"
          notOkText="skipped (no endpoint, timeout, or connection refused)"
        />
        <StatusRow
          label="Dependencies"
          ok={c ? c.had_dependencies : null}
          okText="audited against OSV / typosquat database"
          notOkText="skipped (no manifest, or parse error)"
        />

        {/* Static rows — always shown regardless of coverage data. */}
        <li className="hg-row hg-row-static">
          <span className="hg-mark" aria-hidden="true">·</span>
          <span className="hg-row-label">Dynamic invocation tests</span>
          <span className="hg-row-text">
            not opted in (read-only scan per ADR-007)
          </span>
        </li>
        <li className="hg-row hg-row-static">
          <span className="hg-mark" aria-hidden="true">·</span>
          <span className="hg-row-label">Retired rules</span>
          <span className="hg-row-text">
            13 disabled (high false-positive rate — see{" "}
            <code className="hg-mono">agent_docs/detection-rules.md</code>)
          </span>
        </li>
        <li className="hg-row hg-row-static" data-test-asi10>
          <span className="hg-mark" aria-hidden="true">·</span>
          <span className="hg-row-label">Out of scope</span>
          <span className="hg-row-text">
            OWASP Agentic <strong>ASI10</strong> (Agentic Data Poisoning) —
            not assessable by an MCP scanner; documented honest gap.
          </span>
        </li>

        {/* Dynamic rules-executed row — present only when coverage is known. */}
        {rulesExec != null && rulesTotal != null ? (
          <li className="hg-row hg-row-static">
            <span className="hg-mark" aria-hidden="true">·</span>
            <span className="hg-row-label">Rules executed</span>
            <span className="hg-row-text">
              <span className="hg-mono">{rulesExec}</span> of{" "}
              <span className="hg-mono">{rulesTotal}</span>
              {rulesSkip != null && rulesSkip > 0 ? (
                <>
                  {" "}
                  (<span className="hg-mono">{rulesSkip}</span> skipped — input
                  not available)
                </>
              ) : null}
            </span>
          </li>
        ) : (
          <li className="hg-row hg-row-static hg-row-unknown">
            <span className="hg-mark" aria-hidden="true">—</span>
            <span className="hg-row-label">Rules executed</span>
            <span className="hg-row-text">coverage data unavailable</span>
          </li>
        )}
      </ul>

      {/* ── Optional techniques footer — informative not load-bearing. */}
      {c && c.techniques_run.length > 0 && (
        <p className="hg-foot">
          <span className="hg-foot-key">techniques_run</span>
          <span className="hg-foot-sep">·</span>
          <span className="hg-mono hg-foot-val">
            {c.techniques_run.join(", ")}
          </span>
        </p>
      )}
    </section>
  );
}
