"use client";
/**
 * §2 Testing Depth Panel — categories tested, test count, inputs available,
 * coverage level (HIGH / MEDIUM / LOW).
 *
 * The "what was tested" summary that lets a regulator answer "is this 85
 * a fully-analysed 85 or a coverage-band-LOW 85?" without scrolling. Honest
 * about gaps — the inputs grid surfaces missing source / connection / deps
 * exactly so the page can suggest a re-scan.
 */

import React from "react";
import type { AuditTestingDepth, AuditCoverageLevel } from "@/lib/deep-dive";

const COVERAGE_TONE: Record<AuditCoverageLevel, string> = {
  HIGH: "good",
  MEDIUM: "moderate",
  LOW: "critical",
};

const INPUT_LABELS: Array<{ key: "code" | "runtime" | "deps"; label: string; help: string }> = [
  { key: "code", label: "Source code", help: "Enables AST taint, secret detection, and 98 of 164 rules." },
  { key: "runtime", label: "Runtime connection", help: "Enables H2 initialize-injection + protocol-surface rules." },
  { key: "deps", label: "Dependencies", help: "Enables CVE audit + supply-chain analysis." },
];

export default function TestingDepthPanel({
  depth,
}: {
  depth: AuditTestingDepth | null | undefined;
}) {
  if (!depth) {
    return (
      <section
        className="audit-panel audit-panel-testing audit-panel-empty"
        aria-label="Testing depth — not on file"
      >
        <p className="audit-panel-empty-text">
          Testing depth has not been derived for this scan. Coverage data
          populates with the next scan against migration 014 onward.
        </p>
      </section>
    );
  }

  const tone = COVERAGE_TONE[depth.coverage_level] ?? "moderate";
  const inputs = depth.inputs_available ?? { code: false, runtime: false, deps: false };
  const tested = depth.tests_executed ?? 0;
  const skipped = depth.tests_skipped_no_data ?? 0;
  const total = tested + skipped;

  return (
    <section
      className={`audit-panel audit-panel-testing audit-tone-${tone}`}
      aria-label={`Testing depth: ${depth.coverage_level} coverage, ${tested} tests executed`}
    >
      <header className="audit-section-head">
        <h3 className="audit-section-title">Testing depth</h3>
        <span
          className={`audit-chip audit-chip-${tone}`}
          aria-label={`Coverage level: ${depth.coverage_level}`}
        >
          {depth.coverage_level} COVERAGE
        </span>
      </header>

      <div className="audit-testing-grid">
        <div className="audit-testing-stat">
          <span className="audit-testing-stat-num">{tested}</span>
          <span className="audit-testing-stat-label">
            test{tested === 1 ? "" : "s"} executed
          </span>
        </div>
        <div className="audit-testing-stat">
          <span className="audit-testing-stat-num">{skipped}</span>
          <span className="audit-testing-stat-label">
            skipped — missing inputs
          </span>
        </div>
        <div className="audit-testing-stat">
          <span className="audit-testing-stat-num">
            {depth.categories_tested?.length ?? 0}
          </span>
          <span className="audit-testing-stat-label">categories analysed</span>
        </div>
        {total > 0 && (
          <div className="audit-testing-stat">
            <span className="audit-testing-stat-num">
              {Math.round((tested / total) * 100)}%
            </span>
            <span className="audit-testing-stat-label">applicable rules ran</span>
          </div>
        )}
      </div>

      <div className="audit-testing-inputs" aria-label="Inputs available to the analyzer">
        <h4 className="audit-rec-section-title">Inputs available</h4>
        <ul className="audit-testing-inputs-list">
          {INPUT_LABELS.map(({ key, label, help }) => {
            const present = inputs[key];
            return (
              <li
                key={key}
                className={`audit-input audit-input-${present ? "present" : "missing"}`}
                title={help}
                aria-label={`${label}: ${present ? "available" : "not available"}`}
              >
                <span className="audit-input-glyph" aria-hidden="true">
                  {present ? "✓" : "○"}
                </span>
                <span className="audit-input-label">{label}</span>
              </li>
            );
          })}
        </ul>
      </div>
    </section>
  );
}
