/**
 * RuleCard — the only card on the page. Hero unit.
 *
 * Composition:
 *   - Severity-tinted left rail (6px) keyed to the worst finding severity.
 *   - Header row: rule_id + name + severity pill + OWASP/MITRE chips +
 *                 confidence value.
 *   - For each finding: `<EvidenceChainFlow/>` (the centrepiece), then
 *                       remediation prose.
 *   - Single `<MethodologyDrawer/>` footer link, closed by default.
 *
 * Layout target: 480-640px tall on desktop, single column on mobile.
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
  // Show prose summary only if findings list is empty for any reason
  // (defensive — partition shouldn't put a rule here without findings).
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
          <span className="fv-rule-id">{rule.rule_id}</span>
          <h4 id={`${ruleAnchor(rule.rule_id)}-h`} className="fv-rule-name">
            {rule.name}
          </h4>
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

      <div className="fv-rule-findings">
        {findings.length === 0 ? (
          <p className="fv-rule-empty">No finding details on file.</p>
        ) : (
          findings.map((f, i) => (
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
          ))
        )}
      </div>

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
