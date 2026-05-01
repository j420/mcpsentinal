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
 * Each card also renders a framework cross-walk row below the head — small
 * badges naming the controls the finding violates (EU AI Act Art.12 ☑,
 * ISO 27001 A.8.15 ☑, …). Each badge is a deep-link to the per-framework
 * signed compliance pack PDF for this server, so an auditor can pull the
 * evidence pack for the framework whose control they care about. Backwards
 * compatible: when `framework_controls` is absent the row is suppressed;
 * when it is `[]` an honest "no framework cross-walk" line renders.
 *
 * Client component because of the expand/collapse + filter state.
 */

import React, { useMemo, useState } from "react";
import EvidenceChainViz, { type EvidenceChainData } from "@/components/EvidenceChainViz";
import CategoryDeepDivePanel from "@/components/CategoryDeepDivePanel";
import { RULE_NAMES, type CddFinding } from "@/components/cdd-data";
import {
  FRAMEWORK_SHORT_LABELS,
  type FrameworkId,
} from "@/lib/framework-labels";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3100";

type Severity = "critical" | "high" | "medium" | "low" | "informational";

/**
 * One framework control a finding violates. Shape frozen by Agent 1's
 * ContractFindingResponseSchema — do not infer field paths, consume verbatim.
 */
export interface FrameworkControlRef {
  framework_id: FrameworkId;
  control_id: string;
  control_title: string;
}

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
  /**
   * Framework cross-walk for this finding. ALWAYS an array when present:
   *   - present + non-empty → render badge row
   *   - present + empty     → render honest "no framework cross-walk" line
   *   - absent (older API)  → render nothing (backwards-compat)
   */
  framework_controls?: FrameworkControlRef[];
}

interface Props {
  findings: Finding[];
  scanId?: string | null;
  /**
   * Server slug. Threaded down to finding cards so cross-walk badges can
   * deep-link into the correct per-framework signed PDF endpoint
   * (`/api/v1/servers/<slug>/compliance/<framework_id>.pdf`).
   */
  slug: string;
  /**
   * When true, the tab renders the full category-grouped Deep-Dive view
   * (CategoryDeepDivePanel) instead of the flat severity-sorted list.
   * Default is false: the flat list. The toggle is driven from the
   * server-detail page via `?group=category` and is the user-facing
   * replacement for the old separate "Deep Dive" tab.
   */
  groupByCategory?: boolean;
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

/** Maximum badges rendered inline; the rest collapse into "+N more". */
const MAX_VISIBLE_CROSSWALK_BADGES = 6;

function shortId(id: string): string {
  return id.length > 8 ? id.slice(0, 8) : id;
}

function confLevel(c: number): "good" | "moderate" | "poor" {
  if (c > 0.9) return "good";
  if (c > 0.7) return "moderate";
  return "poor";
}

/**
 * Framework cross-walk row. Renders a badge per declared control + a
 * "+N more" overflow chip beyond MAX_VISIBLE_CROSSWALK_BADGES. Each badge
 * is an `<a>` opening the per-framework signed PDF in a new tab.
 *
 * The component is exported for the test suite — keeping it isolated lets
 * the badge href + truncation rule be asserted without rendering the full
 * card scaffolding.
 */
export function FrameworkCrosswalkRow({
  controls,
  slug,
}: {
  controls: FrameworkControlRef[];
  slug: string;
}) {
  // Honest gap: empty array is signal, not absence. Render explicitly.
  if (controls.length === 0) {
    return (
      <div className="ffc-row ffc-row-empty">
        <span className="ffc-label">Violates</span>
        <span className="ffc-empty-text">no framework cross-walk</span>
      </div>
    );
  }

  const visible = controls.slice(0, MAX_VISIBLE_CROSSWALK_BADGES);
  const overflow = controls.slice(MAX_VISIBLE_CROSSWALK_BADGES);
  const slugEnc = encodeURIComponent(slug);

  // Title attribute on +N chip: list overflow controls so a hover on the
  // chip surfaces "what's hidden" without forcing an expand.
  const overflowTitle = overflow
    .map((c) => `${FRAMEWORK_SHORT_LABELS[c.framework_id]} ${c.control_id}`)
    .join(", ");

  return (
    <div className="ffc-row">
      <span className="ffc-label">Violates</span>
      {visible.map((c, idx) => {
        const fwLabel = FRAMEWORK_SHORT_LABELS[c.framework_id];
        const href = `${API_URL}/api/v1/servers/${slugEnc}/compliance/${c.framework_id}.pdf`;
        return (
          <React.Fragment key={`${c.framework_id}-${c.control_id}-${idx}`}>
            {idx > 0 && <span className="ffc-sep" aria-hidden="true">·</span>}
            <a
              className={`ffc-badge ffc-badge-${c.framework_id}`}
              href={href}
              target="_blank"
              rel="noopener noreferrer"
              title={c.control_title}
              aria-label={`View signed compliance pack for ${fwLabel}`}
            >
              <span className="ffc-fw">{fwLabel}</span>
              <span className="ffc-ctrl">{c.control_id}</span>
              <span className="ffc-mark" aria-hidden="true">☑</span>
            </a>
          </React.Fragment>
        );
      })}
      {overflow.length > 0 && (
        <>
          <span className="ffc-sep" aria-hidden="true">·</span>
          <span className="ffc-more" title={overflowTitle}>
            +{overflow.length} more
          </span>
        </>
      )}
    </div>
  );
}

function FlatFindingsList({
  findings,
  scanId,
  slug,
}: {
  findings: Finding[];
  scanId?: string | null;
  slug: string;
}) {
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

              {/* Framework cross-walk row — renders below severity row, in
                  both collapsed and expanded states. Backwards-compat: when
                  the field is absent we render nothing. */}
              {f.framework_controls !== undefined && (
                <FrameworkCrosswalkRow
                  controls={f.framework_controls}
                  slug={slug}
                />
              )}

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

// ── Default export: thin dispatcher between flat list and category view.
// Hooks live inside FlatFindingsList so the conditional render is safe
// (the deep-dive panel manages its own state and is not subject to the
// flat list's expand/filter hooks).
//
// Grouped view: CategoryDeepDivePanel renders its own card markup. The
// `framework_controls` field is preserved on the FullFinding pass-through
// so a follow-up Cluster C cleanup can extend the panel without re-shaping
// this component's contract. The cross-walk row appears in both views via
// the shared FrameworkCrosswalkRow primitive — the flat list renders it
// inline; the grouped panel mounts it via its own card scaffolding.
export default function FindingsEvidenceTab({
  findings,
  scanId,
  slug,
  groupByCategory = false,
}: Props) {
  if (groupByCategory) {
    const cdd: CddFinding[] = findings.map((f) => ({
      rule_id: f.rule_id,
      severity: f.severity,
    }));
    return (
      <div id="findings-by-category">
        <CategoryDeepDivePanel
          findings={cdd}
          fullFindings={findings}
          slug={slug}
        />
      </div>
    );
  }
  return <FlatFindingsList findings={findings} scanId={scanId} slug={slug} />;
}
