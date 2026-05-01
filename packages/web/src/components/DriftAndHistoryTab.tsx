/**
 * DriftAndHistoryTab — Cluster C Invention #8 (audit doc target IA tab #4).
 *
 * Server Component. Replaces the legacy "Version History" tab with a
 * drift-first headlines view. Score-line moves to the bottom; the lead is
 * "what changed" — tools added/removed, descriptions changed, capabilities
 * introduced, dangerous capabilities introduced, score changes.
 *
 * Contract — frozen against the API agent (Cluster C part 1):
 *
 *   GET /api/v1/servers/:slug/drift?days=<N>
 *
 *   {
 *     data: {
 *       server_slug: string;
 *       window_days: number;
 *       headlines: Array<{
 *         kind: "tool_added" | "tool_removed" | "tool_description_changed"
 *             | "capability_added" | "dangerous_capability_introduced"
 *             | "score_changed";
 *         severity_hint: "neutral" | "elevated" | "degrading" | "improving";
 *         occurred_at: string;
 *         summary: string;
 *         ref?: { tool_name?: string | null; from?: string | null; to?: string | null };
 *       }>;
 *       score_history: Array<{ scanned_at: string; score: number }>;
 *       trend: "neutral" | "improving" | "degrading" | "insufficient_data";
 *     };
 *   }
 *
 * Three-layer fallback:
 *   1. fetch ok + headlines populated → render the headlines list + sparkline.
 *   2. fetch ok + headlines:[] but score_history populated →
 *      "no tool-set drift in last <N> days" + sparkline still rendered.
 *   3. trend === "insufficient_data" → explicit "not enough scan history yet"
 *      panel (regardless of headline count).
 *   4. fetch 404 / network failure / parse failure → "Drift data unavailable
 *      for this scan" panel.
 *
 * Cache — `next: { revalidate: 300 }` matches the API Cache-Control window
 * and the SignedEvidencePack pattern. Cluster B reviewer M1 lesson: the
 * page must NOT be force-dynamic, and components MUST opt into the
 * 300-second revalidate window explicitly so each page load reuses the
 * cached aggregation.
 *
 * Accessibility:
 *   - sparkline carries `role="img"` + aria-label describing the score range.
 *   - trend chip exposes its trend value as text + an aria-label so screen
 *     readers don't have to interpret colour.
 *   - relative timestamps carry a `title` with the absolute ISO so the
 *     hover hint is the audit-grade time.
 */
import React from "react";

// ── Contract Types (authoritative — frozen against API agent) ──────────────

export type DriftHeadlineKind =
  | "tool_added"
  | "tool_removed"
  | "tool_description_changed"
  | "capability_added"
  | "dangerous_capability_introduced"
  | "score_changed";

export type DriftSeverityHint =
  | "neutral"
  | "elevated"
  | "degrading"
  | "improving";

export type DriftTrend =
  | "neutral"
  | "improving"
  | "degrading"
  | "insufficient_data";

export interface DriftHeadlineRef {
  tool_name?: string | null;
  from?: string | null;
  to?: string | null;
}

export interface DriftHeadline {
  kind: DriftHeadlineKind;
  severity_hint: DriftSeverityHint;
  occurred_at: string;
  summary: string;
  ref?: DriftHeadlineRef;
}

export interface DriftScorePoint {
  scanned_at: string;
  score: number;
}

export interface DriftAndHistoryData {
  server_slug: string;
  window_days: number;
  headlines: DriftHeadline[];
  score_history: DriftScorePoint[];
  trend: DriftTrend;
}

interface DriftAndHistoryResponse {
  data: DriftAndHistoryData;
}

// ── Props ───────────────────────────────────────────────────────────────────

export interface DriftAndHistoryTabProps {
  slug: string;
  apiUrl: string;
  /** Window in days. Threaded into the API query. Defaults to 90 if omitted. */
  days?: number;
}

// ── Vocabulary maps (display-only, no client-side relabelling of API data) ─

const KIND_GLYPH: Record<DriftHeadlineKind, string> = {
  tool_added: "+",
  tool_removed: "−",
  tool_description_changed: "≈",
  capability_added: "▸",
  dangerous_capability_introduced: "⚠",
  score_changed: "△",
};

const KIND_LABEL: Record<DriftHeadlineKind, string> = {
  tool_added: "Tool added",
  tool_removed: "Tool removed",
  tool_description_changed: "Description changed",
  capability_added: "Capability added",
  dangerous_capability_introduced: "Dangerous capability introduced",
  score_changed: "Score changed",
};

const TREND_LABEL: Record<DriftTrend, string> = {
  neutral: "NEUTRAL",
  improving: "IMPROVING",
  degrading: "DEGRADING",
  insufficient_data: "INSUFFICIENT DATA",
};

// Trend → declared CSS token. Cluster B reviewer m2 lesson: every var() must
// resolve to an existing declared token in globals.css. --text-1 does not
// exist — use --text instead.
const TREND_TINT: Record<DriftTrend, string> = {
  improving: "var(--good)",
  degrading: "var(--critical)",
  neutral: "var(--text-2)",
  insufficient_data: "var(--text-3)",
};

const ALLOWED_DAYS_VALUES = [30, 90, 365] as const;
const DEFAULT_DAYS = 90;

// ── Helpers ────────────────────────────────────────────────────────────────

function clampDays(v: number | undefined): number {
  if (typeof v !== "number" || !Number.isFinite(v) || v <= 0) return DEFAULT_DAYS;
  // Snap to nearest allowed value so the link group stays in lockstep with
  // the API query.
  for (const allowed of ALLOWED_DAYS_VALUES) {
    if (v === allowed) return v;
  }
  return DEFAULT_DAYS;
}

function fmtAbsolute(iso: string): string {
  try {
    const d = new Date(iso);
    return d.toLocaleString("en-US", {
      year: "numeric", month: "short", day: "numeric",
      hour: "2-digit", minute: "2-digit",
    });
  } catch {
    return iso;
  }
}

export function fmtRelativeTime(iso: string, now: number = Date.now()): string {
  if (!iso) return "—";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "—";
  const diff = now - t;
  if (diff < 0) {
    // Future timestamp — clock skew. Render the absolute, never invent
    // "in the future" copy.
    try {
      return new Date(iso).toLocaleDateString("en-US", { month: "short", day: "numeric" });
    } catch {
      return iso;
    }
  }
  if (diff < 60_000) return "just now";
  if (diff < 3_600_000) {
    const m = Math.floor(diff / 60_000);
    return `${m}m ago`;
  }
  if (diff < 86_400_000) {
    const h = Math.floor(diff / 3_600_000);
    return `${h}h ago`;
  }
  if (diff < 30 * 86_400_000) {
    const d = Math.floor(diff / 86_400_000);
    return `${d}d ago`;
  }
  try {
    return new Date(iso).toLocaleDateString("en-US", {
      month: "short", day: "numeric", year: "numeric",
    });
  } catch {
    return iso;
  }
}

// ── Data fetch — null on any failure (mirrors SignedEvidencePack pattern) ──

async function getDriftAndHistory(
  apiUrl: string,
  slug: string,
  days: number,
): Promise<DriftAndHistoryData | null> {
  try {
    const url =
      `${apiUrl}/api/v1/servers/${encodeURIComponent(slug)}/drift?days=${days}`;
    const res = await fetch(url, {
      next: { revalidate: 300 },
      signal: AbortSignal.timeout(4000),
    });
    if (!res.ok) return null;
    const json = (await res.json()) as Partial<DriftAndHistoryResponse>;
    if (!json || !json.data) return null;
    if (!Array.isArray(json.data.headlines)) return null;
    if (!Array.isArray(json.data.score_history)) return null;
    if (typeof json.data.trend !== "string") return null;
    return json.data as DriftAndHistoryData;
  } catch {
    return null;
  }
}

// ── Sub-components ─────────────────────────────────────────────────────────

function HeadlineRow({ headline }: { headline: DriftHeadline }): React.ReactElement {
  const glyph = KIND_GLYPH[headline.kind];
  const label = KIND_LABEL[headline.kind];
  return (
    <li
      className={`dah-headline dah-headline-${headline.severity_hint}`}
      data-headline-kind={headline.kind}
    >
      <span
        className={`dah-glyph dah-glyph-${headline.severity_hint}`}
        aria-label={label}
        title={label}
      >
        {glyph}
      </span>
      <div className="dah-headline-body">
        <div className="dah-headline-summary">{headline.summary}</div>
        {headline.ref && (
          headline.ref.tool_name ||
          headline.ref.from != null ||
          headline.ref.to != null
        ) && (
          <div className="dah-headline-ref" data-headline-ref>
            {headline.ref.tool_name && (
              <span className="dah-ref-tool">
                <span className="dah-ref-key">tool:</span>{" "}
                <span className="dah-ref-mono">{headline.ref.tool_name}</span>
              </span>
            )}
            {(headline.ref.from != null || headline.ref.to != null) && (
              <span className="dah-ref-delta">
                <span className="dah-ref-mono">
                  {headline.ref.from ?? "—"}
                </span>
                <span className="dah-ref-arrow" aria-hidden="true"> → </span>
                <span className="dah-ref-mono">
                  {headline.ref.to ?? "—"}
                </span>
              </span>
            )}
          </div>
        )}
      </div>
      <time
        className="dah-when"
        dateTime={headline.occurred_at}
        title={fmtAbsolute(headline.occurred_at)}
      >
        {fmtRelativeTime(headline.occurred_at)}
      </time>
    </li>
  );
}

interface SparklineProps {
  points: DriftScorePoint[];
}

function Sparkline({ points }: SparklineProps): React.ReactElement | null {
  if (points.length === 0) return null;

  // Sort by time ascending so the line goes left → right.
  const ordered = [...points].sort(
    (a, b) => Date.parse(a.scanned_at) - Date.parse(b.scanned_at),
  );

  const W = 320;
  const H = 64;
  const PAD_X = 6;
  const PAD_Y = 6;
  const innerW = W - PAD_X * 2;
  const innerH = H - PAD_Y * 2;

  const scoreMin = 0;
  const scoreMax = 100;

  function xFor(i: number, n: number): number {
    if (n <= 1) return PAD_X + innerW / 2;
    return PAD_X + (innerW * i) / (n - 1);
  }
  function yFor(score: number): number {
    const clamped = Math.max(scoreMin, Math.min(scoreMax, score));
    // Higher score → higher visual position (y near top).
    return PAD_Y + innerH * (1 - clamped / scoreMax);
  }

  const polyPoints = ordered
    .map((p, i) => `${xFor(i, ordered.length).toFixed(1)},${yFor(p.score).toFixed(1)}`)
    .join(" ");

  const first = ordered[0]!;
  const last = ordered[ordered.length - 1]!;
  const ariaLabel =
    `Score history: ${ordered.length} ${ordered.length === 1 ? "point" : "points"}, ` +
    `from ${first.score} on ${fmtAbsolute(first.scanned_at)} ` +
    `to ${last.score} on ${fmtAbsolute(last.scanned_at)}.`;

  return (
    <svg
      className="dah-sparkline"
      width={W}
      height={H}
      viewBox={`0 0 ${W} ${H}`}
      role="img"
      aria-label={ariaLabel}
      data-dah-sparkline
      data-point-count={ordered.length}
    >
      {/* Axis baseline at score=0 + reference at score=100 */}
      <line
        x1={PAD_X} x2={W - PAD_X}
        y1={yFor(0)} y2={yFor(0)}
        stroke="var(--border)"
        strokeWidth="1"
        strokeDasharray="2 3"
      />
      {ordered.length > 1 && (
        <polyline
          points={polyPoints}
          fill="none"
          stroke="var(--accent-2)"
          strokeWidth="1.5"
          strokeLinejoin="round"
          strokeLinecap="round"
        />
      )}
      {ordered.map((p, i) => (
        <circle
          key={i}
          className="dah-spark-dot"
          cx={xFor(i, ordered.length)}
          cy={yFor(p.score)}
          r="2"
          fill="var(--accent-2)"
        >
          <title>
            {p.score} on {fmtAbsolute(p.scanned_at)}
          </title>
        </circle>
      ))}
    </svg>
  );
}

function WindowSelector({ slug, days }: { slug: string; days: number }): React.ReactElement {
  // Anchor links query the current page with a different `?days=` value.
  // Mirrors the `?group=category` pattern from FindingsEvidenceTab toggle.
  const slugEnc = encodeURIComponent(slug);
  return (
    <nav className="dah-window" role="group" aria-label="Drift window selector">
      <span className="dah-window-label">Window:</span>
      {ALLOWED_DAYS_VALUES.map((d, i) => {
        const isActive = d === days;
        return (
          <React.Fragment key={d}>
            {i > 0 && <span className="dah-window-sep" aria-hidden="true">·</span>}
            <a
              className={`dah-window-link${isActive ? " dah-window-active" : ""}`}
              href={`/servers/${slugEnc}?days=${d}#tab-drift-history`}
              aria-current={isActive ? "page" : undefined}
              data-dah-window={d}
            >
              {d === 365 ? "1y" : `${d}d`}
            </a>
          </React.Fragment>
        );
      })}
    </nav>
  );
}

// ── Fallback panels ────────────────────────────────────────────────────────

function UnavailablePanel(): React.ReactElement {
  return (
    <section className="sd-section dah-section" data-dah-state="unavailable">
      <div className="dah-eyebrow">WHAT CHANGED</div>
      <h2 className="sd-section-title">Drift &amp; History</h2>
      <div className="dah-empty" role="status">
        <div className="dah-empty-title">Drift data unavailable for this scan</div>
        <p className="dah-empty-sub">
          The drift endpoint did not return data for this server. This may be because
          the scan completed before drift indexing was wired in, or because the API has
          not been upgraded. Score history is still available via the public history
          endpoint directly.
        </p>
      </div>
    </section>
  );
}

function InsufficientDataPanel(
  { data, slug }: { data: DriftAndHistoryData; slug: string },
): React.ReactElement {
  return (
    <section className="sd-section dah-section" data-dah-state="insufficient-data">
      <div className="dah-section-head">
        <div>
          <div className="dah-eyebrow">WHAT CHANGED — last {data.window_days} days</div>
          <h2 className="sd-section-title">Drift &amp; History</h2>
        </div>
        <div className="dah-section-head-aux">
          <span
            className="dah-trend-chip dah-trend-insufficient_data"
            style={{ color: TREND_TINT.insufficient_data }}
            aria-label="Trend: insufficient data"
            data-dah-trend="insufficient_data"
          >
            Trend: {TREND_LABEL.insufficient_data}
          </span>
          <WindowSelector slug={slug} days={data.window_days} />
        </div>
      </div>
      <div className="dah-empty" role="status">
        <div className="dah-empty-title">
          Not enough scan history yet
        </div>
        <p className="dah-empty-sub">
          The first drift signal needs at least 2 scans recorded for this server. Once
          a second scan completes, tool-set changes, capability changes and score
          movements will appear here.
        </p>
      </div>
    </section>
  );
}

// ── Main component ─────────────────────────────────────────────────────────

export default async function DriftAndHistoryTab({
  slug,
  apiUrl,
  days,
}: DriftAndHistoryTabProps): Promise<React.ReactElement> {
  const effectiveDays = clampDays(days);
  const data = await getDriftAndHistory(apiUrl, slug, effectiveDays);

  // Layer 4 — fetch failed entirely.
  if (!data) return <UnavailablePanel />;

  // Layer 3 — trend explicitly says insufficient_data.
  if (data.trend === "insufficient_data") {
    return <InsufficientDataPanel data={data} slug={slug} />;
  }

  const trendLabel = TREND_LABEL[data.trend];
  const trendTint = TREND_TINT[data.trend];

  const hasHeadlines = data.headlines.length > 0;
  const hasHistory = data.score_history.length > 0;

  // Headlines descending — most recent first. Treat the API order as
  // unspecified; we sort defensively.
  const headlinesDesc = [...data.headlines].sort(
    (a, b) => Date.parse(b.occurred_at) - Date.parse(a.occurred_at),
  );

  return (
    <section className="sd-section dah-section" data-dah-state="ok">
      <div className="dah-section-head">
        <div>
          <div className="dah-eyebrow">WHAT CHANGED — last {data.window_days} days</div>
          <h2 className="sd-section-title">Drift &amp; History</h2>
        </div>
        <div className="dah-section-head-aux">
          <span
            className={`dah-trend-chip dah-trend-${data.trend}`}
            style={{ color: trendTint }}
            aria-label={`Trend: ${trendLabel.toLowerCase()}`}
            data-dah-trend={data.trend}
          >
            Trend: {trendLabel}
          </span>
          <WindowSelector slug={slug} days={data.window_days} />
        </div>
      </div>

      {/* ── Headlines (lead with what changed) ─────────────────────────── */}
      <div className="dah-subsection" data-dah-subsection="headlines">
        <h3 className="dah-subsection-title">Headlines</h3>
        {hasHeadlines ? (
          <ul className="dah-headline-list" aria-label="Drift headlines, most recent first">
            {headlinesDesc.map((h, i) => (
              <HeadlineRow key={`${h.occurred_at}-${i}`} headline={h} />
            ))}
          </ul>
        ) : (
          <p
            className="dah-subsection-empty"
            data-dah-no-drift
          >
            No tool-set drift in the last {data.window_days} days.
          </p>
        )}
      </div>

      {/* ── Score sparkline (relegated below the lead) ────────────────── */}
      {hasHistory && (
        <div className="dah-subsection" data-dah-subsection="sparkline">
          <h3 className="dah-subsection-title">
            Score history
            <span className="dah-subsection-count">{data.score_history.length}</span>
          </h3>
          <div className="dah-sparkline-wrap">
            <Sparkline points={data.score_history} />
          </div>
        </div>
      )}
    </section>
  );
}
