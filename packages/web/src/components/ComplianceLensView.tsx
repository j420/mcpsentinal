"use client";
/**
 * ComplianceLensView — replaces the per-rule taxonomy when
 * `?lens=compliance` is active.
 *
 * Reshapes the deep-dive's `categories[]` (the rule-taxonomy spine) into
 * a `frameworks[]` (the framework-control spine) via the pure
 * `buildComplianceShape` transformer, and renders one card per framework
 * with each control as a row showing:
 *   - control id + title
 *   - status pill (met / unmet / partial / not applicable)
 *   - rule pills mapped to the control (data-trace=`rule:` so the
 *     hover-trace highlight wires straight into the existing taxonomy)
 *   - finding count
 *   - link to the signed compliance report (Phase 5 endpoint)
 *
 * The framework-card header carries an aggregate "N met · M unmet ·
 * K partial · J n/a" line so a compliance officer can scan posture
 * across frameworks at a glance.
 *
 * Honest gaps preserved: when no rules carry framework_controls (older
 * api response, missing cross-walk data), the component renders an
 * explanatory empty state rather than synthesising frameworks.
 *
 * Why a client component:
 *   - The per-control rule list uses data-trace so it must be rendered
 *     into a tree the page-level HoverTraceController can see (works
 *     either way, but keeping it client-rendered means the highlight
 *     responds without a hydration round-trip).
 *   - The transformer is pure — testable in isolation — so the
 *     component itself is just rendering.
 */

import React, { useMemo } from "react";
import {
  buildComplianceShape,
  type ComplianceControl,
  type ComplianceFramework,
  type ComplianceStatus,
} from "@/lib/compliance-shape";
import type { DeepDiveCategory } from "@/lib/deep-dive";

interface ComplianceLensViewProps {
  serverSlug: string;
  categories: ReadonlyArray<DeepDiveCategory>;
  /** API origin used for signed-report download links. */
  apiOrigin: string;
}

const STATUS_LABELS: Record<ComplianceStatus, string> = {
  met: "Met",
  unmet: "Unmet",
  partial: "Partial",
  not_applicable: "N/A",
};

const STATUS_TONE: Record<ComplianceStatus, "good" | "bad" | "warn" | "muted"> =
  {
    met: "good",
    unmet: "bad",
    partial: "warn",
    not_applicable: "muted",
  };

/** Frameworks with a Phase-5 signed-report endpoint. The compliance lens
 *  surfaces a download link only for frameworks where the api can serve
 *  one — others render the cross-walk without the download affordance. */
const SIGNED_REPORT_FRAMEWORKS = new Set<string>([
  "eu_ai_act",
  "iso_27001",
  "owasp_mcp",
  "owasp_asi",
  "cosai_mcp",
  "maestro",
  "mitre_atlas",
]);

function ControlRow({
  control,
  frameworkId,
}: {
  control: ComplianceControl;
  frameworkId: string;
}) {
  const tone = STATUS_TONE[control.status];
  return (
    <li
      className="cl-control"
      data-status={control.status}
      data-tone={tone}
      data-trace={`control:${frameworkId}:${control.control_id}`}
    >
      <div className="cl-control-head">
        <span className="cl-control-id">{control.control_id}</span>
        <span className="cl-control-title">{control.control_title}</span>
        <span className={`cl-status cl-status-${tone}`}>
          {STATUS_LABELS[control.status]}
        </span>
      </div>
      <div className="cl-control-meta">
        <span className="cl-control-counts">
          {control.counts.rules_total} rule
          {control.counts.rules_total === 1 ? "" : "s"}
          {control.counts.finding_count > 0 && (
            <>
              {" · "}
              {control.counts.finding_count} finding
              {control.counts.finding_count === 1 ? "" : "s"}
            </>
          )}
          {control.counts.rules_skipped > 0 && (
            <>
              {" · "}
              {control.counts.rules_skipped} skipped
            </>
          )}
        </span>
        {control.rules.length > 0 && (
          <ul className="cl-control-rules" aria-label="Rules mapped to this control">
            {control.rules.map((r) => (
              <li key={r.rule_id} className="cl-control-rule">
                <a
                  href={`#rule-${r.rule_id}`}
                  className={`cl-control-rule-link cl-control-rule-${r.status}`}
                  data-trace={`rule:${r.rule_id}`}
                  title={`${r.name} · ${r.status}${
                    r.findings_count > 0 ? ` · ${r.findings_count} finding(s)` : ""
                  }`}
                >
                  <code className="cl-control-rule-id">{r.rule_id}</code>
                  {r.findings_count > 0 && (
                    <span className="cl-control-rule-count">
                      {r.findings_count}
                    </span>
                  )}
                </a>
              </li>
            ))}
          </ul>
        )}
      </div>
    </li>
  );
}

function FrameworkCard({
  framework,
  serverSlug,
  apiOrigin,
}: {
  framework: ComplianceFramework;
  serverSlug: string;
  apiOrigin: string;
}) {
  const hasReport = SIGNED_REPORT_FRAMEWORKS.has(framework.framework_id);
  const reportBase = `${apiOrigin}/api/v1/servers/${encodeURIComponent(
    serverSlug,
  )}/compliance/${framework.framework_id}`;
  return (
    <article
      className="cl-fw-card"
      aria-labelledby={`cl-fw-${framework.framework_id}-title`}
    >
      <header className="cl-fw-head">
        <div className="cl-fw-head-text">
          <h3
            id={`cl-fw-${framework.framework_id}-title`}
            className="cl-fw-title"
          >
            {framework.framework_label}
          </h3>
          <p className="cl-fw-counts">
            {framework.counts.controls_total} controls ·{" "}
            <span className="cl-fw-counts-met">
              {framework.counts.controls_met} met
            </span>
            {" · "}
            <span className="cl-fw-counts-unmet">
              {framework.counts.controls_unmet} unmet
            </span>
            {" · "}
            <span className="cl-fw-counts-partial">
              {framework.counts.controls_partial} partial
            </span>
            {framework.counts.controls_not_applicable > 0 && (
              <>
                {" · "}
                <span className="cl-fw-counts-na">
                  {framework.counts.controls_not_applicable} n/a
                </span>
              </>
            )}
          </p>
        </div>
        {hasReport && (
          <div className="cl-fw-actions">
            <a
              className="cl-fw-action"
              href={`${reportBase}.html`}
              target="_blank"
              rel="noopener noreferrer"
              title="Signed compliance report (HTML)"
            >
              HTML
            </a>
            <a
              className="cl-fw-action"
              href={`${reportBase}.pdf`}
              target="_blank"
              rel="noopener noreferrer"
              title="Signed compliance report (PDF, regulator-filable)"
            >
              PDF
            </a>
            <a
              className="cl-fw-action"
              href={`${reportBase}.json`}
              target="_blank"
              rel="noopener noreferrer"
              title="Signed compliance report (canonical JSON envelope)"
            >
              JSON
            </a>
          </div>
        )}
      </header>
      <ul className="cl-control-list">
        {framework.controls.map((c) => (
          <ControlRow
            key={c.control_id}
            control={c}
            frameworkId={framework.framework_id}
          />
        ))}
      </ul>
    </article>
  );
}

export default function ComplianceLensView({
  serverSlug,
  categories,
  apiOrigin,
}: ComplianceLensViewProps) {
  const frameworks = useMemo(
    () => buildComplianceShape(categories),
    [categories],
  );

  if (frameworks.length === 0) {
    return (
      <section className="cl-empty" aria-labelledby="cl-empty-title">
        <h2 id="cl-empty-title" className="cl-empty-title">
          Compliance cross-walk not on file
        </h2>
        <p className="cl-empty-msg">
          No rule on this server's deep-dive payload carries a framework
          control mapping. The compliance lens needs the cross-walk
          metadata to restructure the page by framework. This is an api-
          side gap (likely an older deploy or a missing methodology
          manifest), not a data problem with this server.
        </p>
      </section>
    );
  }

  return (
    <section id="dd-section-compliance" className="cl-view" aria-labelledby="cl-view-title">
      <header className="cl-view-head">
        <h2 id="cl-view-title" className="cl-view-title">
          Compliance posture
        </h2>
        <p className="cl-view-sub">
          The same scan data, restructured by framework control instead of
          by rule category. Status per control is mechanically derived
          from the rules mapped to it — no LLM judgement (ADR-006). For
          regulator-filable artefacts, click the HTML/PDF/JSON links per
          framework — those are signed (HMAC-SHA256, RFC 8785) and
          independently verifiable.
        </p>
      </header>
      <div className="cl-fw-grid">
        {frameworks.map((fw) => (
          <FrameworkCard
            key={fw.framework_id}
            framework={fw}
            serverSlug={serverSlug}
            apiOrigin={apiOrigin}
          />
        ))}
      </div>
    </section>
  );
}
