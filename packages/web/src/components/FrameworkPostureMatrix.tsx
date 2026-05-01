/**
 * FrameworkPostureMatrix
 * ──────────────────────
 * Server Component. Renders, in place of the legacy single-framework OWASP MCP
 * grid, a 7-row matrix of regulator-facing control coverage across every
 * compliance framework MCP Sentinel ships (EU AI Act, ISO 27001, OWASP MCP,
 * OWASP ASI, CoSAI, MAESTRO, MITRE ATLAS).
 *
 * Contract — owned by the API agent and consumed verbatim here. The shape
 * below mirrors `GET /api/v1/servers/:slug/compliance` exactly. Do NOT
 * re-derive field names from intuition; if the API changes, both ends update
 * the contract together.
 *
 * Resilience strategy:
 *   1. Single fetch on render (RSC) with `next: { revalidate: 300 }` matching
 *      the existing API Cache-Control window.
 *   2. On 404 (endpoint not deployed) or any network/parse failure, fall back
 *      to the legacy OWASP MCP Top 10 grid using `owasp_coverage_fallback`
 *      from the page so removing the section above does not regress old API
 *      deployments. When the fallback prop is also absent, render an honest
 *      "Posture unavailable for this scan" panel — never a hidden empty
 *      section.
 *   3. Honest gaps (`not_applicable > 0`) are rendered visibly. They are the
 *      proof of intellectual honesty and must never collapse to zero width.
 *
 * Accessibility: each status bar has `role="img"` + an `aria-label` describing
 * the breakdown in plain language. Per-segment titles annotate hover for
 * sighted users.
 */
import React from "react";

// ── Contract Types (authoritative — frozen against API agent) ──────────────

export type FrameworkPostureFrameworkId =
  | "eu_ai_act"
  | "iso_27001"
  | "owasp_mcp"
  | "owasp_asi"
  | "cosai_mcp"
  | "maestro"
  | "mitre_atlas";

export type ControlStatusKey = "met" | "partial" | "unmet" | "not_applicable";

export type CoverageBand = "high" | "medium" | "low" | "minimal";

export interface FrameworkPostureControlCounts {
  met: number;
  partial: number;
  unmet: number;
  not_applicable: number;
  total: number;
}

export interface FrameworkPostureDownloadPaths {
  json: string;
  html: string;
  pdf: string;
  badge_svg: string;
}

export interface FrameworkPostureRow {
  framework_id: FrameworkPostureFrameworkId;
  framework_name: string;
  framework_version: string;
  controls: FrameworkPostureControlCounts;
  overall_status: ControlStatusKey;
  coverage_band: CoverageBand;
  download_paths: FrameworkPostureDownloadPaths;
}

export interface FrameworkPostureData {
  server_slug: string;
  server_name: string;
  last_assessed_at: string | null;
  rules_version: string;
  frameworks: FrameworkPostureRow[];
}

interface FrameworkPostureResponse {
  data: FrameworkPostureData;
}

// ── Props ───────────────────────────────────────────────────────────────────

export interface FrameworkPostureMatrixProps {
  slug: string;
  apiUrl: string;
  /**
   * Legacy OWASP MCP Top 10 boolean coverage map kept on the page for
   * backwards compatibility. When the new aggregate endpoint is unavailable
   * (404 / network failure), this is rendered so the section never disappears.
   */
  owasp_coverage_fallback?: Record<string, boolean> | null;
}

// ── Status / Coverage Vocabulary (display-only; never re-labels API names) ─

const STATUS_PILL_LABEL: Record<ControlStatusKey, string> = {
  met: "Met",
  partial: "Partial",
  unmet: "Unmet",
  not_applicable: "N/A",
};

const STATUS_BAR_LABEL: Record<ControlStatusKey, string> = {
  met: "met",
  partial: "partial",
  unmet: "unmet",
  not_applicable: "not applicable",
};

const COVERAGE_BAND_LABEL: Record<CoverageBand, string> = {
  high: "HIGH coverage",
  medium: "MEDIUM coverage",
  low: "LOW coverage",
  minimal: "MINIMAL coverage",
};

// Bar segment ordering — left to right, "good" → "bad" → "honest gap".
// Honest gaps render last so they are always visible at the right edge.
const BAR_ORDER: ControlStatusKey[] = ["met", "partial", "unmet", "not_applicable"];

// Fallback OWASP MCP Top 10 names for the legacy grid path only.
const OWASP_FALLBACK_NAMES: Record<string, string> = {
  MCP01: "Prompt Injection",
  MCP02: "Tool Poisoning",
  MCP03: "Command Injection",
  MCP04: "Data Exfiltration",
  MCP05: "Privilege Escalation",
  MCP06: "Excessive Permissions",
  MCP07: "Insecure Configuration",
  MCP08: "Dependency Vulnerabilities",
  MCP09: "Logging & Monitoring",
  MCP10: "Supply Chain",
};

// ── Helpers ────────────────────────────────────────────────────────────────

function formatRelativeTime(iso: string | null): string {
  if (!iso) return "never assessed";
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return "unknown";
  const diff = Date.now() - then;
  const minutes = Math.round(diff / 60_000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? "" : "s"} ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} hour${hours === 1 ? "" : "s"} ago`;
  const days = Math.round(hours / 24);
  if (days < 30) return `${days} day${days === 1 ? "" : "s"} ago`;
  const months = Math.round(days / 30);
  if (months < 12) return `${months} month${months === 1 ? "" : "s"} ago`;
  const years = Math.round(months / 12);
  return `${years} year${years === 1 ? "" : "s"} ago`;
}

function buildBarAriaLabel(framework_name: string, counts: FrameworkPostureControlCounts): string {
  return (
    `${framework_name} control coverage: ` +
    `${counts.met} met, ${counts.partial} partial, ${counts.unmet} unmet, ` +
    `${counts.not_applicable} not applicable, of ${counts.total} total controls.`
  );
}

// ── Data fetch — null on any failure (mirrors SignedEvidencePack pattern) ──

async function getFrameworkPosture(
  apiUrl: string,
  slug: string
): Promise<FrameworkPostureData | null> {
  try {
    const res = await fetch(
      // Hotfix PR #218 — the aggregate moved from `/compliance` (which
      // collided with the Phase-5 ComplianceTab consumer) to
      // `/compliance-summary`. The signed per-framework endpoints
      // (`/compliance/<framework>.{json,html,pdf}` etc.) and the
      // judge-confirmed-findings tab are unaffected.
      `${apiUrl}/api/v1/servers/${encodeURIComponent(slug)}/compliance-summary`,
      {
        next: { revalidate: 300 },
        signal: AbortSignal.timeout(4000),
      }
    );
    if (!res.ok) return null;
    const json = (await res.json()) as Partial<FrameworkPostureResponse>;
    if (!json || !json.data) return null;
    if (!Array.isArray(json.data.frameworks)) return null;
    return json.data as FrameworkPostureData;
  } catch {
    return null;
  }
}

// ── Sub-components ─────────────────────────────────────────────────────────

interface BarSegmentProps {
  status: ControlStatusKey;
  count: number;
  total: number;
  framework_name: string;
}

function BarSegment({ status, count, total, framework_name }: BarSegmentProps): React.ReactElement | null {
  if (count <= 0) return null;
  const pct = total > 0 ? (count / total) * 100 : 0;
  const widthStyle: React.CSSProperties = { width: `${pct}%` };
  return (
    <span
      className={`fpm-bar-segment fpm-bar-${status}`}
      style={widthStyle}
      title={`${framework_name}: ${count} ${STATUS_BAR_LABEL[status]} of ${total}`}
      aria-label={`${count} ${STATUS_BAR_LABEL[status]}`}
    />
  );
}

function StatusBar({
  framework_name,
  counts,
}: {
  framework_name: string;
  counts: FrameworkPostureControlCounts;
}): React.ReactElement {
  const label = buildBarAriaLabel(framework_name, counts);
  return (
    <div className="fpm-bar" role="img" aria-label={label}>
      {BAR_ORDER.map((status) => (
        <BarSegment
          key={status}
          status={status}
          count={counts[status]}
          total={counts.total}
          framework_name={framework_name}
        />
      ))}
    </div>
  );
}

function FrameworkRow({ framework }: { framework: FrameworkPostureRow }): React.ReactElement {
  const { framework_name, framework_version, controls, overall_status, coverage_band, download_paths } = framework;
  return (
    <div
      className={`fpm-row fpm-overall-${overall_status}`}
      title={`Open ${framework_name} per-control detail (coming soon)`}
      data-framework-id={framework.framework_id}
    >
      <div className="fpm-row-label">
        <span className="fpm-row-name">{framework_name}</span>
        <span className="fpm-row-version">{framework_version}</span>
      </div>

      <StatusBar framework_name={framework_name} counts={controls} />

      <div className="fpm-row-counts">
        <span className="fpm-count fpm-count-met" title={`${controls.met} met`}>
          {controls.met}
        </span>
        <span className="fpm-count-sep" aria-hidden="true">/</span>
        <span className="fpm-count fpm-count-partial" title={`${controls.partial} partial`}>
          {controls.partial}
        </span>
        <span className="fpm-count-sep" aria-hidden="true">/</span>
        <span className="fpm-count fpm-count-unmet" title={`${controls.unmet} unmet`}>
          {controls.unmet}
        </span>
        <span className="fpm-count-sep" aria-hidden="true">/</span>
        <span className="fpm-count fpm-count-na" title={`${controls.not_applicable} not applicable (honest gap)`}>
          {controls.not_applicable}
        </span>
        <span className="fpm-count-total" aria-label={`of ${controls.total} total`}>
          of {controls.total}
        </span>
      </div>

      <div className="fpm-row-meta">
        <span
          className={`fpm-status-pill fpm-status-${overall_status}`}
          aria-label={`Overall status: ${STATUS_PILL_LABEL[overall_status]}`}
        >
          {STATUS_PILL_LABEL[overall_status]}
        </span>
        <span
          className={`fpm-coverage-band fpm-coverage-${coverage_band}`}
          aria-label={COVERAGE_BAND_LABEL[coverage_band]}
        >
          {COVERAGE_BAND_LABEL[coverage_band]}
        </span>
      </div>

      <div className="fpm-row-downloads" aria-label={`Signed compliance pack downloads for ${framework_name}`}>
        <span className="fpm-row-downloads-label">Open signed pack</span>
        <span className="fpm-row-downloads-arrow" aria-hidden="true">→</span>
        <a className="fpm-dl" href={download_paths.pdf} aria-label={`Download ${framework_name} signed PDF`}>
          PDF
        </a>
        <span className="fpm-dl-sep" aria-hidden="true">|</span>
        <a className="fpm-dl" href={download_paths.html} aria-label={`Download ${framework_name} signed HTML`}>
          HTML
        </a>
        <span className="fpm-dl-sep" aria-hidden="true">|</span>
        <a className="fpm-dl" href={download_paths.json} aria-label={`Download ${framework_name} signed JSON`}>
          JSON
        </a>
        <span className="fpm-dl-sep" aria-hidden="true">|</span>
        <a className="fpm-dl" href={download_paths.badge_svg} aria-label={`Download ${framework_name} badge SVG`}>
          Badge
        </a>
      </div>
    </div>
  );
}

// ── Fallback panels ────────────────────────────────────────────────────────

function OwaspFallbackSection({
  owasp_coverage,
}: {
  owasp_coverage: Record<string, boolean>;
}): React.ReactElement {
  return (
    <section id="owasp" className="sd-section fpm-fallback" data-fpm-fallback="owasp">
      <h2 className="sd-section-title">OWASP MCP Top 10 Coverage</h2>
      <p className="sd-section-sub">
        Pass = no findings in this category. Fail = issues detected. (Showing legacy single-framework view —
        framework posture matrix unavailable for this scan.)
      </p>
      <div className="sd-owasp-grid">
        {Object.entries(owasp_coverage).map(([id, clean]) => (
          <div
            key={id}
            className={`sd-owasp-item ${clean ? "sd-owasp-clean" : "sd-owasp-dirty"}`}
          >
            <span className="sd-owasp-indicator" />
            <span className="sd-owasp-id">{id}</span>
            <span className="sd-owasp-name">{OWASP_FALLBACK_NAMES[id] ?? id}</span>
            <span className="sd-owasp-status">{clean ? "Pass" : "Fail"}</span>
          </div>
        ))}
      </div>
    </section>
  );
}

function UnavailableSection(): React.ReactElement {
  return (
    <section id="framework-posture" className="sd-section fpm-section" data-fpm-state="unavailable">
      <div className="fpm-eyebrow">REGULATOR-FACING — assessed control coverage</div>
      <h2 className="sd-section-title">Framework Posture</h2>
      <div className="fpm-empty" role="status">
        <div className="fpm-empty-title">Posture unavailable for this scan</div>
        <p className="fpm-empty-sub">
          The compliance posture endpoint did not return data for this server. This may be because the scan
          predates the framework registry, or because the API has not yet been upgraded. Per-finding compliance
          mapping (where present) is still available in the Findings tab below.
        </p>
      </div>
    </section>
  );
}

// ── Main component ─────────────────────────────────────────────────────────

export default async function FrameworkPostureMatrix({
  slug,
  apiUrl,
  owasp_coverage_fallback,
}: FrameworkPostureMatrixProps): Promise<React.ReactElement> {
  const data = await getFrameworkPosture(apiUrl, slug);

  // Endpoint missing or empty → fall back to legacy OWASP grid (if data is on
  // the page) or to an explicit unavailable panel. Either way we render a
  // visible section — never silently collapse.
  if (!data || data.frameworks.length === 0) {
    if (owasp_coverage_fallback && Object.keys(owasp_coverage_fallback).length > 0) {
      return <OwaspFallbackSection owasp_coverage={owasp_coverage_fallback} />;
    }
    return <UnavailableSection />;
  }

  // Aggregate summary line — "X of Y controls met across Z frameworks".
  let metTotal = 0;
  let controlTotal = 0;
  for (const fw of data.frameworks) {
    metTotal += fw.controls.met;
    controlTotal += fw.controls.total;
  }
  const summary = `${metTotal} of ${controlTotal} controls met across ${data.frameworks.length} framework${
    data.frameworks.length === 1 ? "" : "s"
  } · last assessed ${formatRelativeTime(data.last_assessed_at)}`;

  return (
    <section id="framework-posture" className="sd-section fpm-section" data-fpm-state="ok">
      <div className="fpm-eyebrow">REGULATOR-FACING — assessed control coverage</div>
      <h2 className="sd-section-title">
        Framework Posture
        <span className="sd-section-count" aria-label={`${data.frameworks.length} frameworks assessed`}>
          {data.frameworks.length}
        </span>
      </h2>
      <p className="sd-section-sub fpm-summary" data-fpm-summary>
        {summary}
      </p>

      <div className="fpm-matrix" role="list" aria-label="Per-framework control coverage">
        {data.frameworks.map((fw) => (
          <div role="listitem" key={fw.framework_id}>
            <FrameworkRow framework={fw} />
          </div>
        ))}
      </div>

      <div className="fpm-legend" aria-hidden="true">
        <span className="fpm-legend-item">
          <span className="fpm-legend-swatch fpm-bar-met" /> Met
        </span>
        <span className="fpm-legend-item">
          <span className="fpm-legend-swatch fpm-bar-partial" /> Partial
        </span>
        <span className="fpm-legend-item">
          <span className="fpm-legend-swatch fpm-bar-unmet" /> Unmet
        </span>
        <span className="fpm-legend-item">
          <span className="fpm-legend-swatch fpm-bar-not_applicable" /> N/A (honest gap)
        </span>
      </div>
    </section>
  );
}
