/**
 * EvidenceChainViz — Renders a structured evidence chain as a visual flow.
 *
 * Displays the source→propagation→sink data flow that proves a security finding,
 * with mitigation checks and impact assessment. Each link is independently verifiable.
 *
 * Also includes an inline ConfidenceIndicator — the confidence bar is shown
 * at the top of each evidence chain rather than as a separate component,
 * because confidence is meaningless without the evidence that produced it.
 *
 * Server component — no client-side state needed.
 * Gracefully renders nothing if evidence_chain is null/undefined (most findings
 * won't have structured evidence chains until rules are progressively upgraded).
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

export interface EvidenceChainData {
  links: EvidenceLink[];
  confidence_factors: ConfidenceFactor[];
  confidence: number;
  threat_reference?: ThreatReference;
}

// ─── Constants ───────────────────────────────────────────────────────────────

const SOURCE_TYPE_LABELS: Record<string, string> = {
  "user-parameter": "User Parameter",
  "external-content": "External Content",
  "file-content": "File Content",
  "environment": "Environment",
  "database-content": "Database Content",
  "agent-output": "Agent Output",
  "initialize-field": "Initialize Field",
};

const SINK_TYPE_LABELS: Record<string, string> = {
  "command-execution": "Command Execution",
  "code-evaluation": "Code Evaluation",
  "sql-execution": "SQL Execution",
  "file-write": "File Write",
  "network-send": "Network Send",
  "deserialization": "Deserialization",
  "template-render": "Template Render",
  "credential-exposure": "Credential Exposure",
  "config-modification": "Config Modification",
  "privilege-grant": "Privilege Grant",
};

const PROPAGATION_LABELS: Record<string, string> = {
  "direct-pass": "Direct Pass",
  "variable-assignment": "Variable Assignment",
  "string-concatenation": "String Concatenation",
  "template-literal": "Template Literal",
  "function-call": "Function Call",
  "cross-tool-flow": "Cross-Tool Flow",
  "schema-unconstrained": "Schema Unconstrained",
  "description-directive": "Description Directive",
};

const IMPACT_LABELS: Record<string, string> = {
  "remote-code-execution": "Remote Code Execution",
  "data-exfiltration": "Data Exfiltration",
  "credential-theft": "Credential Theft",
  "denial-of-service": "Denial of Service",
  "privilege-escalation": "Privilege Escalation",
  "session-hijack": "Session Hijack",
  "config-poisoning": "Config Poisoning",
  "cross-agent-propagation": "Cross-Agent Propagation",
};

const EXPLOITABILITY_LABELS: Record<string, string> = {
  trivial: "Trivial",
  moderate: "Moderate",
  complex: "Complex",
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

function confLevel(c: number): "high" | "medium" | "low" {
  if (c >= 0.70) return "high";
  if (c >= 0.45) return "medium";
  return "low";
}

function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return s.slice(0, max) + "\u2026";
}

// ─── Sub-components ──────────────────────────────────────────────────────────

function SourceNode({ link }: { link: SourceLink }) {
  return (
    <div className="ec-node ec-node-source">
      <div className="ec-node-badge ec-badge-source">SOURCE</div>
      <div className="ec-node-type">{SOURCE_TYPE_LABELS[link.source_type] ?? link.source_type}</div>
      <div className="ec-node-location">{link.location}</div>
      <div className="ec-node-observed">{truncate(link.observed, 120)}</div>
      <div className="ec-node-rationale">{link.rationale}</div>
    </div>
  );
}

function PropagationNode({ link }: { link: PropagationLink }) {
  return (
    <div className="ec-node ec-node-prop">
      <div className="ec-node-badge ec-badge-prop">FLOW</div>
      <div className="ec-node-type">{PROPAGATION_LABELS[link.propagation_type] ?? link.propagation_type}</div>
      <div className="ec-node-location">{link.location}</div>
      <div className="ec-node-observed">{truncate(link.observed, 100)}</div>
    </div>
  );
}

function SinkNode({ link }: { link: SinkLink }) {
  return (
    <div className="ec-node ec-node-sink">
      <div className="ec-node-badge ec-badge-sink">SINK</div>
      <div className="ec-node-type">{SINK_TYPE_LABELS[link.sink_type] ?? link.sink_type}</div>
      <div className="ec-node-location">{link.location}</div>
      <div className="ec-node-observed">{truncate(link.observed, 100)}</div>
      {link.cve_precedent && (
        <span className="ec-cve">{link.cve_precedent}</span>
      )}
    </div>
  );
}

function MitigationNode({ link }: { link: MitigationLink }) {
  return (
    <div className={`ec-node ec-node-mit ${link.present ? "ec-mit-present" : "ec-mit-absent"}`}>
      <div className={`ec-node-badge ${link.present ? "ec-badge-mit-yes" : "ec-badge-mit-no"}`}>
        {link.present ? "\u2713 MITIGATED" : "\u2717 UNMITIGATED"}
      </div>
      <div className="ec-node-type">{link.mitigation_type.replace(/-/g, " ")}</div>
      <div className="ec-node-detail">{link.detail}</div>
    </div>
  );
}

function ImpactNode({ link }: { link: ImpactLink }) {
  return (
    <div className="ec-node ec-node-impact">
      <div className="ec-node-badge ec-badge-impact">IMPACT</div>
      <div className="ec-node-type">{IMPACT_LABELS[link.impact_type] ?? link.impact_type}</div>
      <div className="ec-impact-meta">
        <span className="ec-impact-scope">{link.scope.replace(/-/g, " ")}</span>
        <span className={`ec-impact-exploit ec-exploit-${link.exploitability}`}>
          {EXPLOITABILITY_LABELS[link.exploitability] ?? link.exploitability}
        </span>
      </div>
      <div className="ec-node-detail">{link.scenario}</div>
    </div>
  );
}

function renderLink(link: EvidenceLink, index: number) {
  switch (link.type) {
    case "source":
      return <SourceNode key={index} link={link} />;
    case "propagation":
      return <PropagationNode key={index} link={link} />;
    case "sink":
      return <SinkNode key={index} link={link} />;
    case "mitigation":
      return <MitigationNode key={index} link={link} />;
    case "impact":
      return <ImpactNode key={index} link={link} />;
    default:
      return null;
  }
}

// ─── Main Component ──────────────────────────────────────────────────────────

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
    return (
      <div className="ec-confidence-only">
        <span className="ec-conf-label">Confidence</span>
        <div className="ec-conf-bar-track">
          <div className={`ec-conf-bar-fill ec-conf-${level}`} style={{ width: `${Math.round(confidence * 100)}%` }} />
        </div>
        <span className={`ec-conf-pct ec-conf-${level}`}>{Math.round(confidence * 100)}%</span>
      </div>
    );
  }

  // Full evidence chain visualization
  if (!chain) return null;

  // Separate flow links (source, propagation, sink) from context links (mitigation, impact)
  const flowLinks = chain.links.filter((l) => l.type === "source" || l.type === "propagation" || l.type === "sink");
  const mitigations = chain.links.filter((l): l is MitigationLink => l.type === "mitigation");
  const impacts = chain.links.filter((l): l is ImpactLink => l.type === "impact");

  const level = confLevel(chain.confidence);

  return (
    <div className="ec-chain">
      {/* ── Confidence Bar ───────────────────────────────────── */}
      <div className="ec-confidence">
        <span className="ec-conf-label">Confidence</span>
        <div className="ec-conf-bar-track">
          <div className={`ec-conf-bar-fill ec-conf-${level}`} style={{ width: `${Math.round(chain.confidence * 100)}%` }} />
        </div>
        <span className={`ec-conf-pct ec-conf-${level}`}>{Math.round(chain.confidence * 100)}%</span>
      </div>

      {/* ── Data Flow Timeline ───────────────────────────────── */}
      {flowLinks.length > 0 && (
        <div className="ec-flow">
          <div className="ec-flow-label">Evidence Chain</div>
          <div className="ec-timeline">
            {flowLinks.map((link, i) => (
              <div key={i} className="ec-timeline-step">
                {renderLink(link, i)}
                {i < flowLinks.length - 1 && (
                  <div className="ec-connector">
                    <svg width="20" height="24" viewBox="0 0 20 24" fill="none">
                      <path d="M10 0 L10 18 M5 14 L10 20 L15 14" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                    </svg>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Mitigations ──────────────────────────────────────── */}
      {mitigations.length > 0 && (
        <div className="ec-mitigations">
          <div className="ec-flow-label">Mitigation Checks</div>
          <div className="ec-mit-grid">
            {mitigations.map((link, i) => (
              <MitigationNode key={i} link={link} />
            ))}
          </div>
        </div>
      )}

      {/* ── Impact ───────────────────────────────────────────── */}
      {impacts.length > 0 && (
        <div className="ec-impacts">
          {impacts.map((link, i) => (
            <ImpactNode key={i} link={link} />
          ))}
        </div>
      )}

      {/* ── Threat Reference ─────────────────────────────────── */}
      {chain.threat_reference && (
        <div className="ec-reference">
          <span className="ec-ref-id">{chain.threat_reference.id}</span>
          <span className="ec-ref-title">{chain.threat_reference.title}</span>
          {chain.threat_reference.year && (
            <span className="ec-ref-year">({chain.threat_reference.year})</span>
          )}
        </div>
      )}

      {/* ── Confidence Factor Breakdown ──────────────────────── */}
      {chain.confidence_factors.length > 0 && (
        <details className="ec-factors">
          <summary className="ec-factors-summary">Confidence factors ({chain.confidence_factors.length})</summary>
          <div className="ec-factors-list">
            {chain.confidence_factors.map((f, i) => (
              <div key={i} className="ec-factor">
                <span className={`ec-factor-adj ${f.adjustment >= 0 ? "ec-factor-pos" : "ec-factor-neg"}`}>
                  {f.adjustment >= 0 ? "+" : ""}{f.adjustment.toFixed(2)}
                </span>
                <span className="ec-factor-name">{f.factor}</span>
              </div>
            ))}
          </div>
        </details>
      )}
    </div>
  );
}
