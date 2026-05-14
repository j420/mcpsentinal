/**
 * CompactRuleRow — compact, expandable row for passed and skipped rules.
 *
 * Keeps the per-rule scroll cost low while preserving the five-entity
 * model. Default state: single-line summary (status icon + rule id +
 * name + status label / missing inputs). Click to expand a body that
 * renders:
 *   - the rule's TESTS panel (humanized strategy list)
 *   - a small "Tested cleanly" / "Skipped — needs X" block
 *   - the methodology drawer (frameworks / backing / edge cases)
 *
 * Native `<details>` — no React state, server-renderable, accessible
 * by keyboard out of the box.
 */

import React from "react";
import MethodologyDrawer from "./methodology-drawer";
import type { CascadeRule } from "./view-model";
import type { DeepDiveSkipInput } from "@/lib/deep-dive";

export interface CompactRuleRowProps {
  rule: CascadeRule;
}

function ruleAnchor(ruleId: string): string {
  return `rule-${ruleId.toLowerCase()}`;
}

function humanizeStrategy(id: string): string {
  if (!id) return "";
  const tokens = id.split(/[-_]+/);
  const head = tokens.slice(0, 2).join("-").toLowerCase();
  const tail = tokens.slice(2).map((t) => t.toLowerCase()).join(" ");
  const NAMED: Record<string, string> = {
    "ast-taint": "AST taint analysis",
    "taint-path": "Taint-path verification",
    "sanitizer-verified": "Sanitiser verification",
    "schema-shape": "Schema-shape inference",
    "linguistic-pattern": "Linguistic pattern match",
    "entropy-threshold": "Entropy threshold",
    "structural-parse": "Structural parse",
    "graph-traversal": "Capability-graph traversal",
    "annotation-check": "Annotation conformance",
    "regex-blocklist": "Pattern blocklist",
    "version-compare": "Version comparison",
    "similarity-levenshtein": "Levenshtein similarity",
    "context-window": "Context-window analysis",
  };
  const named = NAMED[head];
  if (named) {
    return tail ? `${named} · ${tail}` : named;
  }
  return tokens
    .map((t) => (t.length === 0 ? t : t[0].toUpperCase() + t.slice(1)))
    .join(" ");
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

function skipInputCTA(input: DeepDiveSkipInput): string {
  switch (input) {
    case "source_code":
      return "Add a GitHub URL to your server registration.";
    case "connection":
      return "Register a live MCP endpoint we can reach.";
    case "dependencies":
      return "Expose a package manifest (package.json / pyproject.toml).";
  }
}

export default function CompactRuleRow({
  rule,
}: CompactRuleRowProps): React.ReactElement {
  const status = rule.status;
  const tests = Array.isArray(rule.methodology?.edge_case_strategies)
    ? rule.methodology.edge_case_strategies
    : [];
  const technique = rule.methodology?.technique ?? "";
  const cveValidations = Array.isArray(rule.validated_by_cve)
    ? rule.validated_by_cve
    : [];

  const isSkipped = status === "skipped";
  const missingInputs = isSkipped
    ? rule.skip_reason?.missing_inputs ?? []
    : [];
  const skipSummary = isSkipped ? rule.skip_reason?.summary : null;

  const statusLabel = isSkipped ? "Skipped" : "Passed";
  const statusGlyph = isSkipped ? "○" : "✓";
  const inlineHint =
    isSkipped && missingInputs.length > 0
      ? `Needs ${missingInputs.map(skipInputLabel).join(" + ")}`
      : isSkipped
        ? "Awaiting data"
        : "Tested cleanly";

  return (
    <details
      className="fv-crow"
      data-status={status}
      id={ruleAnchor(rule.rule_id)}
    >
      <summary className="fv-crow-summary">
        <span
          className={`fv-crow-glyph fv-crow-glyph-${status}`}
          aria-hidden="true"
        >
          {statusGlyph}
        </span>
        <code className="fv-crow-id">{rule.rule_id}</code>
        <span className="fv-crow-name">{rule.name}</span>
        <span className={`fv-crow-status fv-crow-status-${status}`}>
          {statusLabel}
        </span>
        <span className="fv-crow-hint">{inlineHint}</span>
        <span className="fv-crow-chevron" aria-hidden="true">
          <svg viewBox="0 0 16 16" width="14" height="14" fill="none">
            <path
              d="M4 6l4 4 4-4"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </span>
      </summary>

      <div className="fv-crow-body">
        {rule.summary && <p className="fv-crow-summary-prose">{rule.summary}</p>}

        {/* TESTS panel — visible inside the expanded compact row so the
            five-entity model is honoured for every rule. */}
        <section
          className="fv-rule-tests fv-crow-tests"
          aria-label={`Tests for rule ${rule.rule_id}`}
        >
          <header className="fv-rule-section-head">
            <span className="fv-rule-section-eyebrow">Tests</span>
            <span className="fv-rule-section-count">
              {tests.length} strateg{tests.length === 1 ? "y" : "ies"}
            </span>
          </header>
          {technique && (
            <div className="fv-rule-tech-row">
              <span className="fv-rule-tech-label">Primary technique</span>
              <code className="fv-rule-tech">{technique}</code>
            </div>
          )}
          {tests.length === 0 ? (
            <p className="fv-rule-tests-empty">
              No edge-case strategies declared in the rule&apos;s CHARTER.md.
            </p>
          ) : (
            <ol className="fv-rule-tests-list">
              {tests.map((t, i) => (
                <li key={i} className="fv-rule-test">
                  <span className="fv-rule-test-num">{i + 1}</span>
                  <div className="fv-rule-test-body">
                    <p className="fv-rule-test-title">{humanizeStrategy(t)}</p>
                    <code className="fv-rule-test-id">{t}</code>
                  </div>
                </li>
              ))}
            </ol>
          )}
        </section>

        {/* Status callout — variant per status. */}
        {isSkipped ? (
          <section className="fv-rule-skipped" aria-label="Skip reason">
            <span className="fv-rule-skipped-icon" aria-hidden="true">
              ○
            </span>
            <div className="fv-rule-skipped-body">
              <p className="fv-rule-skipped-headline">
                {skipSummary ?? "Not yet tested for this server."}
              </p>
              {missingInputs.length > 0 && (
                <ul className="fv-rule-skipped-needs">
                  {missingInputs.map((input) => (
                    <li key={input} className="fv-rule-skipped-need">
                      <span className="fv-rule-skipped-need-label">
                        Needs · {skipInputLabel(input)}
                      </span>
                      <span className="fv-rule-skipped-need-cta">
                        {skipInputCTA(input)}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </section>
        ) : (
          <section className="fv-rule-clean" aria-label="Passed cleanly">
            <span className="fv-rule-clean-icon" aria-hidden="true">
              ✓
            </span>
            <div className="fv-rule-clean-body">
              <p className="fv-rule-clean-headline">
                Tested cleanly — no evidence of this attack vector on file.
              </p>
              <p className="fv-rule-clean-detail">
                The strategies above were applied to this server and no
                triggering pattern was found.
              </p>
            </div>
          </section>
        )}

        <footer className="fv-rule-foot">
          <MethodologyDrawer
            methodology={rule.methodology}
            frameworks={rule.framework_controls}
            backing={rule.backing}
            cveValidations={cveValidations}
          />
        </footer>
      </div>
    </details>
  );
}
