/**
 * EvidenceChainViz — Regulator-grade evidence presentation.
 *
 * Renders structured evidence chains in a 5-question format designed for
 * compliance officers, enterprise security teams, and regulators:
 *
 *   1. WHAT was found?       — The vulnerability and its attack surface
 *   2. WHERE in the code?    — Exact location from source through propagation to sink
 *   3. WHY is this dangerous? — Real-world impact with CVE precedent and exploit scenario
 *   4. HOW CONFIDENT are we? — Quantified confidence with transparent factor breakdown
 *   5. HOW TO VERIFY?        — Step-by-step instructions a reviewer can independently follow
 *
 * Each section provides 3-4 lines of descriptive prose suitable for
 * framework-wide compliance reports (EU AI Act Art. 12/14/15, ISO 42001, NIST AI RMF).
 *
 * Gracefully renders nothing if evidence_chain is null/undefined.
 * Falls back to a minimal confidence indicator when only confidence is available.
 */

import React from "react";

// ─── Types (matching packages/analyzer/src/evidence.ts) ──────────────────────

interface SourceLink {
  type: "source";
  source_type: string;
  location: string;
  observed: string;
  rationale: string;
}

interface PropagationLink {
  type: "propagation";
  propagation_type: string;
  location: string;
  observed: string;
}

interface SinkLink {
  type: "sink";
  sink_type: string;
  location: string;
  observed: string;
  cve_precedent?: string;
}

interface MitigationLink {
  type: "mitigation";
  mitigation_type: string;
  present: boolean;
  location: string;
  detail: string;
}

interface ImpactLink {
  type: "impact";
  impact_type: string;
  scope: string;
  exploitability: string;
  scenario: string;
}

type EvidenceLink = SourceLink | PropagationLink | SinkLink | MitigationLink | ImpactLink;

interface ConfidenceFactor {
  factor: string;
  adjustment: number;
  rationale: string;
}

interface ThreatReference {
  id: string;
  title: string;
  url?: string;
  year?: number;
  relevance: string;
}

interface VerificationStep {
  step_type: string;
  instruction: string;
  target: string;
  expected_observation?: string;
}

export interface EvidenceChainData {
  links: EvidenceLink[];
  confidence_factors: ConfidenceFactor[];
  confidence: number;
  threat_reference?: ThreatReference;
  verification_steps?: VerificationStep[];
}

// ─── Human-readable label maps ──────────────────────────────────────────────

const SOURCE_TYPE_LABELS: Record<string, string> = {
  "user-parameter": "User-Controlled Parameter",
  "external-content": "External Content Source",
  "file-content": "File System Content",
  "environment": "Environment Variable",
  "database-content": "Database Content",
  "agent-output": "Agent Output",
  "initialize-field": "MCP Initialize Field",
};

const SINK_TYPE_LABELS: Record<string, string> = {
  "command-execution": "Operating System Command Execution",
  "code-evaluation": "Dynamic Code Evaluation",
  "sql-execution": "SQL Statement Execution",
  "file-write": "File System Write Operation",
  "network-send": "Outbound Network Request",
  "deserialization": "Object Deserialization",
  "template-render": "Template Engine Rendering",
  "credential-exposure": "Credential or Secret Exposure",
  "config-modification": "Configuration Modification",
  "privilege-grant": "Privilege Grant or Escalation",
};

const IMPACT_LABELS: Record<string, string> = {
  "remote-code-execution": "Remote Code Execution (RCE)",
  "data-exfiltration": "Data Exfiltration",
  "credential-theft": "Credential Theft",
  "denial-of-service": "Denial of Service (DoS)",
  "privilege-escalation": "Privilege Escalation",
  "session-hijack": "Session Hijacking",
  "config-poisoning": "Configuration Poisoning",
  "cross-agent-propagation": "Cross-Agent Attack Propagation",
};

const EXPLOITABILITY_LABELS: Record<string, string> = {
  trivial: "Trivial — No special conditions required",
  moderate: "Moderate — Requires specific preconditions",
  complex: "Complex — Multiple conditions must align",
};

const SCOPE_LABELS: Record<string, string> = {
  "server-host": "Server Host System",
  "user-data": "User Data and Privacy",
  "connected-services": "Connected Services and APIs",
  "build-environment": "Build and CI/CD Environment",
  "ai-client": "AI Client and Agent Context",
  "internal-details": "Internal System Details",
};

const STEP_TYPE_LABELS: Record<string, string> = {
  "inspect-source": "Source Code Inspection",
  "inspect-schema": "Schema Inspection",
  "inspect-description": "Description Inspection",
  "test-input": "Input Testing",
  "check-config": "Configuration Check",
  "check-dependency": "Dependency Check",
  "trace-flow": "Data Flow Trace",
  "compare-baseline": "Baseline Comparison",
};

// ─── Helpers ────────────────────────────────────────────────────────────────

function confLevel(c: number): "high" | "medium" | "low" {
  if (c >= 0.70) return "high";
  if (c >= 0.45) return "medium";
  return "low";
}

function confLabel(c: number): string {
  if (c >= 0.85) return "Very High";
  if (c >= 0.70) return "High";
  if (c >= 0.55) return "Moderate";
  if (c >= 0.45) return "Low-Moderate";
  return "Low";
}

// ─── Section 1: WHAT was found? ─────────────────────────────────────────────

function WhatSection({ sources, sinks, impacts }: { sources: SourceLink[]; sinks: SinkLink[]; impacts: ImpactLink[] }) {
  const source = sources[0];
  const sink = sinks[0];
  const impact = impacts[0];

  return (
    <div className="ec5-section ec5-what">
      <div className="ec5-section-header">
        <span className="ec5-section-num">1</span>
        <h4 className="ec5-section-title">What Was Found</h4>
      </div>
      <div className="ec5-section-body">
        {source && (
          <p className="ec5-prose">
            <strong>Untrusted data entry point identified.</strong>{" "}
            A {(SOURCE_TYPE_LABELS[source.source_type] ?? source.source_type).toLowerCase()} at{" "}
            <code className="ec5-loc">{source.location}</code> introduces data into the processing
            pipeline without adequate boundary controls. The observed input pattern
            is <code className="ec5-code">{source.observed.length > 100 ? source.observed.slice(0, 100) + "\u2026" : source.observed}</code>.
          </p>
        )}
        {source?.rationale && (
          <p className="ec5-prose ec5-rationale">
            {source.rationale}
          </p>
        )}
        {sink && (
          <p className="ec5-prose">
            <strong>Dangerous operation reached.</strong>{" "}
            This data reaches a {(SINK_TYPE_LABELS[sink.sink_type] ?? sink.sink_type).toLowerCase()} at{" "}
            <code className="ec5-loc">{sink.location}</code>,
            where the observed operation is <code className="ec5-code">{sink.observed.length > 100 ? sink.observed.slice(0, 100) + "\u2026" : sink.observed}</code>.
            {sink.cve_precedent && (
              <> This pattern has documented real-world exploitation precedent ({sink.cve_precedent}).</>
            )}
          </p>
        )}
        {impact && (
          <p className="ec5-prose">
            <strong>Potential impact: {IMPACT_LABELS[impact.impact_type] ?? impact.impact_type}.</strong>{" "}
            If exploited, an attacker could compromise {(SCOPE_LABELS[impact.scope] ?? impact.scope).toLowerCase()}.{" "}
            Exploitability is assessed as {(EXPLOITABILITY_LABELS[impact.exploitability] ?? impact.exploitability).toLowerCase()}.
          </p>
        )}
        {!source && !sink && impacts.length > 0 && (
          <p className="ec5-prose">
            <strong>Structural vulnerability identified.</strong>{" "}
            {impact!.scenario}
          </p>
        )}
      </div>
    </div>
  );
}

// ─── Section 2: WHERE in the code? ──────────────────────────────────────────

function WhereSection({ sources, propagations, sinks }: {
  sources: SourceLink[]; propagations: PropagationLink[]; sinks: SinkLink[]
}) {
  if (sources.length === 0 && sinks.length === 0) return null;

  return (
    <div className="ec5-section ec5-where">
      <div className="ec5-section-header">
        <span className="ec5-section-num">2</span>
        <h4 className="ec5-section-title">Where in the Code</h4>
      </div>
      <div className="ec5-section-body">
        <p className="ec5-prose">
          The data flow traverses {1 + propagations.length + (sinks.length > 0 ? 1 : 0)} location{(1 + propagations.length + (sinks.length > 0 ? 1 : 0)) !== 1 ? "s" : ""} from
          entry point to dangerous operation.
          {propagations.length > 0
            ? ` The data passes through ${propagations.length} intermediate transformation${propagations.length !== 1 ? "s" : ""} before reaching the sink, each of which could have applied sanitization but did not.`
            : " The data flows directly from source to sink with no intermediate transformations or sanitization points."
          }
        </p>
        <div className="ec5-flow-chain">
          {sources.map((s, i) => (
            <div key={`s-${i}`} className="ec5-flow-node ec5-flow-source">
              <div className="ec5-flow-badge">ENTRY</div>
              <div className="ec5-flow-loc">{s.location}</div>
              <div className="ec5-flow-obs">{s.observed.length > 80 ? s.observed.slice(0, 80) + "\u2026" : s.observed}</div>
            </div>
          ))}
          {sources.length > 0 && (propagations.length > 0 || sinks.length > 0) && (
            <div className="ec5-flow-arrow" aria-hidden="true">
              <svg width="16" height="20" viewBox="0 0 16 20" fill="none"><path d="M8 0v14M3 11l5 6 5-6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></svg>
            </div>
          )}
          {propagations.map((p, i) => (
            <React.Fragment key={`p-${i}`}>
              <div className="ec5-flow-node ec5-flow-prop">
                <div className="ec5-flow-badge">FLOW</div>
                <div className="ec5-flow-loc">{p.location}</div>
                <div className="ec5-flow-obs">{p.observed.length > 80 ? p.observed.slice(0, 80) + "\u2026" : p.observed}</div>
              </div>
              {(i < propagations.length - 1 || sinks.length > 0) && (
                <div className="ec5-flow-arrow" aria-hidden="true">
                  <svg width="16" height="20" viewBox="0 0 16 20" fill="none"><path d="M8 0v14M3 11l5 6 5-6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></svg>
                </div>
              )}
            </React.Fragment>
          ))}
          {sinks.map((s, i) => (
            <div key={`k-${i}`} className="ec5-flow-node ec5-flow-sink">
              <div className="ec5-flow-badge">DANGER</div>
              <div className="ec5-flow-loc">{s.location}</div>
              <div className="ec5-flow-obs">{s.observed.length > 80 ? s.observed.slice(0, 80) + "\u2026" : s.observed}</div>
              {s.cve_precedent && <div className="ec5-flow-cve">{s.cve_precedent}</div>}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Section 3: WHY is this dangerous? ──────────────────────────────────────

function WhySection({ impacts, mitigations, reference }: {
  impacts: ImpactLink[]; mitigations: MitigationLink[]; reference?: ThreatReference
}) {
  const absentMitigations = mitigations.filter(m => !m.present);
  const presentMitigations = mitigations.filter(m => m.present);

  return (
    <div className="ec5-section ec5-why">
      <div className="ec5-section-header">
        <span className="ec5-section-num">3</span>
        <h4 className="ec5-section-title">Why This Is Dangerous</h4>
      </div>
      <div className="ec5-section-body">
        {impacts.map((impact, i) => (
          <div key={i} className="ec5-impact-block">
            <p className="ec5-prose">
              <strong>{IMPACT_LABELS[impact.impact_type] ?? impact.impact_type}.</strong>{" "}
              {impact.scenario}
            </p>
            <div className="ec5-impact-meta">
              <span className="ec5-impact-scope">
                Scope: {SCOPE_LABELS[impact.scope] ?? impact.scope}
              </span>
              <span className={`ec5-impact-exploit ec5-exploit-${impact.exploitability}`}>
                Exploitability: {EXPLOITABILITY_LABELS[impact.exploitability] ?? impact.exploitability}
              </span>
            </div>
          </div>
        ))}
        {absentMitigations.length > 0 && (
          <div className="ec5-mitigations">
            <p className="ec5-prose ec5-mit-header">
              <strong>Missing security controls ({absentMitigations.length}):</strong>{" "}
              The following mitigation measures were checked during analysis and found to be absent.
              Each represents a defense layer that, if implemented, would reduce or eliminate the exploitability of this finding.
            </p>
            <div className="ec5-mit-list">
              {absentMitigations.map((m, i) => (
                <div key={i} className="ec5-mit-item ec5-mit-absent">
                  <span className="ec5-mit-icon">\u2717</span>
                  <div className="ec5-mit-content">
                    <strong>{m.mitigation_type.replace(/-/g, " ")}</strong>
                    <p>{m.detail}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
        {presentMitigations.length > 0 && (
          <div className="ec5-mitigations ec5-mitigations-present">
            <p className="ec5-prose ec5-mit-header">
              <strong>Controls detected ({presentMitigations.length}):</strong>
            </p>
            <div className="ec5-mit-list">
              {presentMitigations.map((m, i) => (
                <div key={i} className="ec5-mit-item ec5-mit-present">
                  <span className="ec5-mit-icon">\u2713</span>
                  <div className="ec5-mit-content">
                    <strong>{m.mitigation_type.replace(/-/g, " ")}</strong>
                    <p>{m.detail}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
        {reference && (
          <div className="ec5-reference">
            <span className="ec5-ref-label">Threat Intelligence Reference</span>
            <div className="ec5-ref-detail">
              <span className="ec5-ref-id">{reference.id}</span>
              <span className="ec5-ref-title">{reference.title}</span>
              {reference.year && <span className="ec5-ref-year">({reference.year})</span>}
            </div>
            <p className="ec5-ref-relevance">{reference.relevance}</p>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Section 4: HOW CONFIDENT are we? ───────────────────────────────────────

function ConfidenceSection({ confidence, factors }: { confidence: number; factors: ConfidenceFactor[] }) {
  const level = confLevel(confidence);
  const pct = Math.round(confidence * 100);

  return (
    <div className="ec5-section ec5-confidence">
      <div className="ec5-section-header">
        <span className="ec5-section-num">4</span>
        <h4 className="ec5-section-title">Confidence Assessment</h4>
      </div>
      <div className="ec5-section-body">
        <div className="ec5-conf-display">
          <div className="ec5-conf-score">
            <span className={`ec5-conf-pct ec5-conf-${level}`}>{pct}%</span>
            <span className={`ec5-conf-label-text ec5-conf-${level}`}>{confLabel(confidence)}</span>
          </div>
          <div className="ec5-conf-bar-track">
            <div className={`ec5-conf-bar-fill ec5-conf-${level}`} style={{ width: `${pct}%` }} />
          </div>
        </div>
        <p className="ec5-prose">
          This finding has been assigned a confidence score of <strong>{pct}%</strong> ({confLabel(confidence).toLowerCase()}).
          Confidence reflects the strength of the evidence chain: higher values indicate that the finding
          was confirmed through multiple independent analysis techniques (e.g., AST-based taint tracking,
          structural pattern matching, or cross-reference with known CVEs). Lower values indicate the
          finding is based on heuristic patterns that may require manual verification.
        </p>
        {factors.length > 0 && (
          <div className="ec5-factors">
            <p className="ec5-factors-header">
              <strong>Confidence factors:</strong> The following analysis signals contributed to the final confidence score.
              Positive adjustments indicate corroborating evidence; negative adjustments indicate uncertainty or partial mitigation.
            </p>
            <div className="ec5-factors-list">
              {factors.map((f, i) => (
                <div key={i} className="ec5-factor-item">
                  <span className={`ec5-factor-adj ${f.adjustment >= 0 ? "ec5-factor-pos" : "ec5-factor-neg"}`}>
                    {f.adjustment >= 0 ? "+" : ""}{f.adjustment.toFixed(2)}
                  </span>
                  <div className="ec5-factor-detail">
                    <strong>{f.factor.replace(/_/g, " ")}</strong>
                    <p>{f.rationale}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Section 5: HOW TO VERIFY? ──────────────────────────────────────────────

function VerifySection({ steps }: { steps: VerificationStep[] }) {
  if (steps.length === 0) return null;

  return (
    <div className="ec5-section ec5-verify">
      <div className="ec5-section-header">
        <span className="ec5-section-num">5</span>
        <h4 className="ec5-section-title">How to Verify</h4>
      </div>
      <div className="ec5-section-body">
        <p className="ec5-prose">
          The following verification steps enable independent confirmation of this finding.
          Each step can be performed by a security reviewer, compliance auditor, or automated
          tooling to validate that the identified vulnerability exists and assess whether
          remediation has been applied.
        </p>
        <div className="ec5-verify-steps">
          {steps.map((step, i) => (
            <div key={i} className="ec5-verify-step">
              <div className="ec5-verify-step-header">
                <span className="ec5-verify-step-num">Step {i + 1}</span>
                <span className="ec5-verify-step-type">{STEP_TYPE_LABELS[step.step_type] ?? step.step_type}</span>
              </div>
              <div className="ec5-verify-step-target">
                <span className="ec5-verify-target-label">Target:</span>
                <code className="ec5-verify-target-val">{step.target}</code>
              </div>
              <p className="ec5-verify-instruction">{step.instruction}</p>
              {step.expected_observation && (
                <div className="ec5-verify-expected">
                  <span className="ec5-verify-expected-label">Expected observation:</span>
                  <p className="ec5-verify-expected-text">{step.expected_observation}</p>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Main Component ─────────────────────────────────────────────────────────

export default function EvidenceChainViz({
  chain,
  confidence,
}: {
  chain: EvidenceChainData | null | undefined;
  /** Standalone confidence for findings without structured chains */
  confidence?: number;
}) {
  // If there's no chain AND no separate confidence, render nothing
  if (!chain && confidence == null) return null;

  // If there's only confidence (no chain), render a minimal confidence indicator
  if (!chain && confidence != null) {
    const level = confLevel(confidence);
    const pct = Math.round(confidence * 100);
    return (
      <div className="ec5-confidence-only">
        <span className="ec5-conf-only-label">Confidence</span>
        <div className="ec5-conf-bar-track">
          <div className={`ec5-conf-bar-fill ec5-conf-${level}`} style={{ width: `${pct}%` }} />
        </div>
        <span className={`ec5-conf-only-pct ec5-conf-${level}`}>{pct}%</span>
      </div>
    );
  }

  if (!chain) return null;

  // Categorize links
  const sources = chain.links.filter((l): l is SourceLink => l.type === "source");
  const propagations = chain.links.filter((l): l is PropagationLink => l.type === "propagation");
  const sinks = chain.links.filter((l): l is SinkLink => l.type === "sink");
  const mitigations = chain.links.filter((l): l is MitigationLink => l.type === "mitigation");
  const impacts = chain.links.filter((l): l is ImpactLink => l.type === "impact");
  const steps = chain.verification_steps ?? [];

  return (
    <div className="ec5-report">
      <div className="ec5-report-header">
        <span className="ec5-report-title">Evidence Report</span>
        <span className={`ec5-report-conf ec5-conf-${confLevel(chain.confidence)}`}>
          {Math.round(chain.confidence * 100)}% confidence
        </span>
      </div>

      <WhatSection sources={sources} sinks={sinks} impacts={impacts} />
      <WhereSection sources={sources} propagations={propagations} sinks={sinks} />
      <WhySection impacts={impacts} mitigations={mitigations} reference={chain.threat_reference} />
      <ConfidenceSection confidence={chain.confidence} factors={chain.confidence_factors} />
      <VerifySection steps={steps} />
    </div>
  );
}
