/**
 * FindingCard — one finding, one frame.
 *
 * Above the fold: rule id, name, severity, confidence, framework chips, CVE
 * precedent badge, one-line claim. Collapsible section reveals the full
 * EvidenceChainViz, remediation, threat refs, and adversarial-fixture count.
 *
 * Pure server component — uses native <details> for the collapse so it works
 * with JS disabled.
 */
import React from "react";
import EvidenceChainViz, { type EvidenceChainData } from "./EvidenceChainViz";
import { RULE_NAMES } from "./cdd-data";

export interface FindingForCard {
  id: string;
  rule_id: string;
  severity: "critical" | "high" | "medium" | "low" | "informational";
  evidence: string;
  remediation: string;
  owasp_category: string | null;
  mitre_technique: string | null;
  confidence?: number;
  evidence_chain?: Record<string, unknown> | null;
}

interface CorpusEntry {
  fixture_count: number;
  cve_replays: string[];
}

interface Props {
  finding: FindingForCard;
  corpus?: CorpusEntry;
}

function confidenceBand(c: number | undefined): "high" | "med" | "low" | "none" {
  if (c == null) return "none";
  if (c >= 0.85) return "high";
  if (c >= 0.6) return "med";
  return "low";
}

function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return s.slice(0, max - 1).trimEnd() + "…";
}

function cvePrecedent(chain: Record<string, unknown> | null | undefined): string | null {
  if (!chain || typeof chain !== "object") return null;
  const sink = (chain as { sink?: { cve_precedent?: string } }).sink;
  if (sink && typeof sink.cve_precedent === "string") return sink.cve_precedent;
  // Fallback: some chains stash refs under threat_reference
  const tr = (chain as { threat_reference?: { id?: string } }).threat_reference;
  if (tr && typeof tr.id === "string" && tr.id.startsWith("CVE-")) return tr.id;
  return null;
}

export default function FindingCard({ finding: f, corpus }: Props) {
  const ruleName = RULE_NAMES[f.rule_id] ?? f.rule_id;
  const cBand = confidenceBand(f.confidence);
  const cve = cvePrecedent(f.evidence_chain);
  const claim = truncate(f.evidence ?? "", 220);

  return (
    <article className={`frame finding-card-v2 finding-${f.severity}`}>
      {/* Header row — rule id + severity + confidence + framework chips */}
      <header className="fcv2-header">
        <span className="eyebrow-mono fcv2-rule-id">{f.rule_id}</span>
        <span className={`sev-badge sev-${f.severity}`}>{f.severity}</span>
        <h3 className="fcv2-rule-name">{ruleName}</h3>
        {f.confidence != null && (
          <span
            className={`fcv2-confidence fcv2-conf-${cBand}`}
            title={`Confidence: ${(f.confidence * 100).toFixed(0)}%`}
          >
            <span className="fcv2-conf-dot" />
            {(f.confidence * 100).toFixed(0)}%
          </span>
        )}
      </header>

      {/* Framework + CVE chip row */}
      {(f.owasp_category || f.mitre_technique || cve || corpus) && (
        <div className="fcv2-chips">
          {f.owasp_category && (
            <span className="sd-finding-tag sd-finding-owasp">{f.owasp_category}</span>
          )}
          {f.mitre_technique && (
            <span className="sd-finding-tag sd-finding-mitre">{f.mitre_technique}</span>
          )}
          {cve && (
            <span className="sd-finding-tag fcv2-cve" title="Real-world CVE precedent">
              {cve}
            </span>
          )}
          {corpus && corpus.fixture_count > 0 && (
            <span
              className="sd-finding-tag fcv2-corpus"
              title={`This rule is regression-tested against ${corpus.fixture_count} adversarial fixtures${
                corpus.cve_replays.length > 0
                  ? ` and ${corpus.cve_replays.length} CVE replays`
                  : ""
              }.`}
            >
              ✓ {corpus.fixture_count} fixtures
              {corpus.cve_replays.length > 0 && ` · ${corpus.cve_replays.length} CVE`}
            </span>
          )}
        </div>
      )}

      {/* One-line claim */}
      <p className="fcv2-claim">{claim}</p>

      {/* Collapsible — full evidence chain + remediation */}
      <details className="fcv2-details">
        <summary className="fcv2-details-summary">
          <span>Evidence chain · verification · remediation</span>
          <span className="fcv2-chevron" aria-hidden>▾</span>
        </summary>
        <div className="fcv2-details-body">
          <EvidenceChainViz
            chain={f.evidence_chain as EvidenceChainData | null | undefined}
            confidence={f.confidence}
          />
          {f.remediation && (
            <div className="fcv2-remediation">
              <span className="eyebrow-mono">REMEDIATION</span>
              <p>{f.remediation}</p>
            </div>
          )}
        </div>
      </details>
    </article>
  );
}
