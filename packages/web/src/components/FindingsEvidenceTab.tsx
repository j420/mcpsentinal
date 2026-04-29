"use client";

/**
 * FindingsEvidenceTab — expandable findings list with severity filter.
 *
 * Replaces the prior inline findings panel. Each card collapses to a single
 * row (severity, rule_id, framework pills, expand chevron) and expands to
 * show: plain-English evidence string, the existing <EvidenceChainViz>
 * structured chain, confidence bar, remediation block. The most-severe
 * finding is pre-expanded on first render.
 *
 * Client component because of the expand/collapse + filter state.
 */

import React, { useMemo, useState } from "react";
import EvidenceChainViz, { type EvidenceChainData } from "@/components/EvidenceChainViz";
import { RULE_NAMES } from "@/components/cdd-data";

type Severity = "critical" | "high" | "medium" | "low" | "informational";

interface Finding {
  id: string;
  rule_id: string;
  severity: Severity;
  evidence: string;
  remediation: string;
  owasp_category: string | null;
  mitre_technique: string | null;
  confidence?: number;
  evidence_chain?: Record<string, unknown> | null;
}

interface Props {
  findings: Finding[];
  scanId?: string | null;
}

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0, high: 1, medium: 2, low: 3, informational: 4,
};

const FILTERS: Array<{ key: "all" | Severity; label: string }> = [
  { key: "all", label: "ALL" },
  { key: "critical", label: "CRITICAL" },
  { key: "high", label: "HIGH" },
  { key: "medium", label: "MEDIUM" },
  { key: "low", label: "LOW" },
  { key: "informational", label: "INFO" },
];

function shortId(id: string): string {
  return id.length > 8 ? id.slice(0, 8) : id;
}

function confLevel(c: number): "good" | "moderate" | "poor" {
  if (c > 0.9) return "good";
  if (c > 0.7) return "moderate";
  return "poor";
}

export default function FindingsEvidenceTab({ findings, scanId }: Props) {
  const sorted = useMemo(
    () => [...findings].sort((a, b) =>
      SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]
        || (b.confidence ?? 0) - (a.confidence ?? 0)
        || a.rule_id.localeCompare(b.rule_id),
    ),
    [findings],
  );

  const counts = useMemo(() => {
    const m: Record<string, number> = { all: sorted.length };
    for (const f of sorted) m[f.severity] = (m[f.severity] ?? 0) + 1;
    return m;
  }, [sorted]);

  const [filter, setFilter] = useState<"all" | Severity>("all");
  const [expanded, setExpanded] = useState<Set<string>>(
    () => new Set(sorted[0] ? [sorted[0].id] : []),
  );

  const visible = filter === "all" ? sorted : sorted.filter((f) => f.severity === filter);

  function toggle(id: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }

  if (sorted.length === 0) {
    return (
      <section className="fet-empty">
        <p className="fet-empty-msg">
          No findings detected. This server passed all enabled detection rules.
        </p>
      </section>
    );
  }

  return (
    <section className="fet-section">
      <div className="fet-filter-row" role="tablist" aria-label="Filter findings by severity">
        {FILTERS.map((f) => {
          const active = f.key === filter;
          const n = counts[f.key] ?? 0;
          if (f.key !== "all" && n === 0) return null;
          return (
            <button
              key={f.key}
              type="button"
              role="tab"
              aria-selected={active}
              className={`fet-pill ${active ? "fet-pill-active" : ""}`}
              onClick={() => setFilter(f.key)}
            >
              {f.label}
              <span className="fet-pill-count">{n}</span>
            </button>
          );
        })}
      </div>

      <ul className="fet-list">
        {visible.map((f) => {
          const isExp = expanded.has(f.id);
          return (
            <li
              key={f.id}
              className={`fet-card fet-card-${f.severity}`}
            >
              <button
                type="button"
                className="fet-card-head"
                aria-expanded={isExp}
                aria-controls={`fet-body-${f.id}`}
                onClick={() => toggle(f.id)}
              >
                <span className="fet-fid">{shortId(f.id)}</span>
                <span className={`sev-badge sev-${f.severity}`}>{f.severity}</span>
                <span className="fet-rule">{f.rule_id}</span>
                <span className="fet-rule-name">
                  {RULE_NAMES[f.rule_id] ?? f.rule_id}
                </span>
                <span className="fet-frameworks">
                  {f.owasp_category && (
                    <span className="fet-fw fet-fw-owasp">
                      OWASP {f.owasp_category}
                    </span>
                  )}
                  {f.mitre_technique && (
                    <span className="fet-fw fet-fw-mitre">
                      MITRE {f.mitre_technique}
                    </span>
                  )}
                </span>
                <span className={`fet-chev ${isExp ? "fet-chev-open" : ""}`} aria-hidden="true">
                  ▾
                </span>
              </button>

              {isExp && (
                <div id={`fet-body-${f.id}`} className="fet-card-body">
                  <p className="fet-evidence-text">{f.evidence}</p>

                  <EvidenceChainViz
                    chain={f.evidence_chain as EvidenceChainData | null | undefined}
                    confidence={f.confidence}
                  />

                  {f.confidence != null && (
                    <div className="fet-conf">
                      <span className="fet-conf-label">confidence</span>
                      <div className="fet-conf-track" aria-hidden="true">
                        <div
                          className="fet-conf-fill"
                          style={{
                            width: `${Math.round((f.confidence ?? 0) * 100)}%`,
                            background: `var(--${confLevel(f.confidence ?? 0)})`,
                          }}
                        />
                      </div>
                      <span className="fet-conf-pct">
                        {Math.round((f.confidence ?? 0) * 100)}%
                      </span>
                    </div>
                  )}

                  {f.remediation && (
                    <div className="fet-rem">
                      <span className="fet-rem-label">Fix</span>
                      <span className="fet-rem-text">{f.remediation}</span>
                    </div>
                  )}

                  <div className="fet-foot">
                    rule_id={f.rule_id} · finding_id={f.id}
                    {scanId && <> · scan={scanId}</>}
                  </div>
                </div>
              )}
            </li>
          );
        })}
      </ul>
    </section>
  );
}
