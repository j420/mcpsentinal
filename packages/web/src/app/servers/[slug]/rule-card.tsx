/**
 * RuleCard — the only card on the page. Hero unit.
 *
 * Composition:
 *   - Severity-tinted left rail (6px) keyed to the worst finding severity.
 *   - Header row: rule_id + name + severity pill + OWASP/MITRE chips +
 *                 confidence value.
 *   - TESTS panel: the rule's edge_case_strategies as a numbered list,
 *                  always visible. This is the "what we test for"
 *                  surface that makes the page's `Tests` entity explicit.
 *   - EVIDENCE panel: per-finding `<EvidenceChainFlow/>` (the
 *                  centrepiece), then remediation prose.
 *   - Single `<MethodologyDrawer/>` footer link, closed by default,
 *                  carrying the secondary metadata (technique, lethal
 *                  edge cases, frameworks, backing, CVE replays).
 *
 * Pure rendering. The drawer is a native `<details>` so the card needs
 * no React state.
 */

import React from "react";
import EvidenceChainFlow from "./evidence-chain-flow";
import MethodologyDrawer from "./methodology-drawer";
import type { RuleWithFindings } from "./view-model";
import type { DeepDiveSeverity } from "@/lib/deep-dive";

export interface RuleCardProps {
  rule: RuleWithFindings;
}

const SEVERITY_LABEL: Record<DeepDiveSeverity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  informational: "Informational",
};

function ruleAnchor(ruleId: string): string {
  return `rule-${ruleId.toLowerCase()}`;
}

function findingAnchor(findingId: string): string {
  return `finding-${findingId}`;
}

export default function RuleCard({ rule }: RuleCardProps): React.ReactElement {
  const sev = rule.worstSeverity;
  const findings = rule.findings;
  const tests = Array.isArray(rule.methodology?.edge_case_strategies)
    ? rule.methodology.edge_case_strategies
    : [];
  const technique = rule.methodology?.technique ?? "";
  const cveValidations = Array.isArray(rule.validated_by_cve)
    ? rule.validated_by_cve
    : [];

  return (
    <article
      className="fv-rule"
      data-severity={sev}
      id={ruleAnchor(rule.rule_id)}
      aria-labelledby={`${ruleAnchor(rule.rule_id)}-h`}
    >
      <header className="fv-rule-head">
        <div className="fv-rule-id-block">
          <span className="fv-rule-eyebrow">Rule</span>
          <div className="fv-rule-id-line">
            <span className="fv-rule-id">{rule.rule_id}</span>
            <h4 id={`${ruleAnchor(rule.rule_id)}-h`} className="fv-rule-name">
              {rule.name}
            </h4>
          </div>
        </div>
        <div className="fv-rule-tags">
          <span
            className={`fv-pill fv-pill-sev fv-pill-sev-${sev}`}
            aria-label={`Severity: ${SEVERITY_LABEL[sev]}`}
          >
            {SEVERITY_LABEL[sev]}
          </span>
          {rule.owasp && (
            <span className="fv-pill fv-pill-frame" title="OWASP mapping">
              {rule.owasp}
            </span>
          )}
          {rule.mitre && (
            <span className="fv-pill fv-pill-frame" title="MITRE ATLAS mapping">
              {rule.mitre}
            </span>
          )}
          <a
            className="fv-rule-permalink"
            href={`#${ruleAnchor(rule.rule_id)}`}
            aria-label={`Permalink to ${rule.rule_id}`}
            title="Copy permalink"
          >
            <svg
              viewBox="0 0 16 16"
              width="14"
              height="14"
              fill="none"
              aria-hidden="true"
            >
              <path
                d="M6.5 9.5a3 3 0 0 1 0-4.2l2.6-2.6a3 3 0 0 1 4.2 4.2l-1 1M9.5 6.5a3 3 0 0 1 0 4.2l-2.6 2.6a3 3 0 0 1-4.2-4.2l1-1"
                stroke="currentColor"
                strokeWidth="1.4"
                strokeLinecap="round"
              />
            </svg>
          </a>
        </div>
      </header>

      {rule.summary && <p className="fv-rule-summary">{rule.summary}</p>}

      {/* ── TESTS panel — what this rule looks for ────────────────── */}
      <section className="fv-rule-tests" aria-labelledby={`${ruleAnchor(rule.rule_id)}-tests`}>
        <header className="fv-rule-section-head">
          <span
            className="fv-rule-section-eyebrow"
            id={`${ruleAnchor(rule.rule_id)}-tests`}
          >
            Tests
          </span>
          {technique && (
            <code className="fv-rule-tech" title="Detection technique">
              {technique}
            </code>
          )}
          <span className="fv-rule-section-count">
            {tests.length} strateg{tests.length === 1 ? "y" : "ies"}
          </span>
        </header>
        {tests.length === 0 ? (
          <p className="fv-rule-tests-empty">
            No edge-case strategies declared in the rule&apos;s CHARTER.md.
          </p>
        ) : (
          <ol className="fv-rule-tests-list">
            {tests.map((t, i) => (
              <li key={i} className="fv-rule-test">
                <span className="fv-rule-test-num">{i + 1}</span>
                <code className="fv-rule-test-body">{t}</code>
              </li>
            ))}
          </ol>
        )}
      </section>

      {/* ── EVIDENCE panel — the per-finding chains ───────────────── */}
      <section
        className="fv-rule-evidences"
        aria-labelledby={`${ruleAnchor(rule.rule_id)}-evidence`}
      >
        <header className="fv-rule-section-head">
          <span
            className="fv-rule-section-eyebrow"
            id={`${ruleAnchor(rule.rule_id)}-evidence`}
          >
            Evidence
          </span>
          <span className="fv-rule-section-count">
            {findings.length} finding{findings.length === 1 ? "" : "s"}
          </span>
        </header>
        {findings.length === 0 ? (
          <p className="fv-rule-empty">No finding details on file.</p>
        ) : (
          <div className="fv-rule-findings">
            {findings.map((f, i) => (
              <section
                key={f.id}
                className="fv-finding"
                id={findingAnchor(f.id)}
                data-severity={f.severity}
                aria-label={`Finding ${i + 1} of ${findings.length}`}
              >
                {findings.length > 1 && (
                  <header className="fv-finding-head">
                    <span className="fv-finding-num">
                      Finding {i + 1} of {findings.length}
                    </span>
                    <span
                      className={`fv-pill fv-pill-sev fv-pill-sev-${f.severity}`}
                    >
                      {SEVERITY_LABEL[f.severity]}
                    </span>
                    <span className="fv-finding-conf">
                      Confidence {Math.round(f.confidence * 100)}%
                    </span>
                  </header>
                )}
                <EvidenceChainFlow
                  chain={f.evidence_chain}
                  fallbackEvidence={f.evidence}
                  findingId={findingAnchor(f.id)}
                />
                {f.remediation && (
                  <aside className="fv-finding-fix">
                    <span className="fv-finding-fix-label">Fix</span>
                    <p className="fv-finding-fix-body">{f.remediation}</p>
                  </aside>
                )}
              </section>
            ))}
          </div>
        )}
      </section>

      <footer className="fv-rule-foot">
        <MethodologyDrawer
          methodology={rule.methodology}
          frameworks={rule.framework_controls}
          backing={rule.backing}
          cveValidations={cveValidations}
        />
      </footer>
    </article>
  );
}
