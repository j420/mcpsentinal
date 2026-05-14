/**
 * RuleCard — full hero card for FINDINGS rules only.
 *
 * Passed and skipped rules render as `<CompactRuleRow/>` instead. This
 * card is reserved for findings so the page leads with proof, not
 * inventory.
 *
 * Composition:
 *   - Severity-tinted left rail keyed to the worst finding severity.
 *   - Header: rule_id chip + name + severity / OWASP / MITRE pills.
 *   - Plain-English summary (the "what this rule means" line).
 *   - TESTS section: humanized strategy list + primary technique row.
 *   - EVIDENCE section: per-finding `<EvidenceChainFlow/>` with the
 *                       full source→propagation→sink→mitigation→impact
 *                       cascade, confidence factors, real-world
 *                       precedent, and "How to verify" steps.
 *   - Methodology drawer footer (collapsed by default).
 */

import React from "react";
import EvidenceChainFlow from "./evidence-chain-flow";
import MethodologyDrawer from "./methodology-drawer";
import type { CascadeRule } from "./view-model";
import type { DeepDiveSeverity } from "@/lib/deep-dive";

export interface RuleCardProps {
  rule: CascadeRule;
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

export default function RuleCard({ rule }: RuleCardProps): React.ReactElement {
  const sev = rule.worstSeverity ?? "informational";
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
      data-status="findings"
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

      {/* TESTS panel — always visible. */}
      <section
        className="fv-rule-tests"
        aria-labelledby={`${ruleAnchor(rule.rule_id)}-tests`}
      >
        <header className="fv-rule-section-head">
          <span
            className="fv-rule-section-eyebrow"
            id={`${ruleAnchor(rule.rule_id)}-tests`}
          >
            Tests
          </span>
          <span className="fv-rule-section-count">
            {tests.length} strateg{tests.length === 1 ? "y" : "ies"}
          </span>
        </header>
        <p className="fv-rule-section-intro">
          How this rule decides. Each strategy below is a deterministic
          analysis the detector runs against the MCP server&apos;s static
          metadata, source code, and (when present) live connection
          handshake.
        </p>
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

      {/* EVIDENCE panel — per-finding vertical cascade. */}
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
        <p className="fv-rule-section-intro">
          What we found. Each finding below carries a structured proof
          chain from <strong>source</strong> (where untrusted data enters)
          through <strong>propagation</strong> (how it flows) to a{" "}
          <strong>sink</strong> (where the dangerous operation occurs),
          including any <strong>mitigations</strong> checked for and the
          potential <strong>impact</strong> if exploited. Every link is
          independently verifiable against the cited location.
        </p>
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
