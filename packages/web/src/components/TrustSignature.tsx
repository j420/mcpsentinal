/**
 * Trust Signature — the verdict block at the top of every server detail page.
 *
 * Replaces the legacy left/right sd-hero split. Reads as one frame: the server
 * identity on the left, the score lineage on the right. Every datum is observable
 * (from the API response) and reproducible (sub-score weights cite the scorer).
 */
import React from "react";

interface ScoreDetail {
  total_score: number;
  code_score: number;
  deps_score: number;
  config_score: number;
  description_score: number;
  behavior_score: number;
  owasp_coverage?: Record<string, boolean>;
  total_score_v2?: number | null;
  techniques_v2?: Record<string, string>;
}

interface ScoreHistoryPoint {
  score: number | null;
  recorded_at: string;
}

interface Props {
  name: string;
  description: string | null;
  author: string | null;
  category: string | null;
  language: string | null;
  license: string | null;
  server_version: string | null;
  github_url: string | null;
  npm_package: string | null;
  pypi_package: string | null;
  connection_status: string | null;
  last_scanned_at: string | null;
  rules_version: string | null;
  score_detail: ScoreDetail | null;
  history: ScoreHistoryPoint[];
}

const SUBSCORES: Array<{ key: keyof ScoreDetail; label: string; weight: number }> = [
  { key: "code_score", label: "CODE", weight: 1.6 },
  { key: "deps_score", label: "DEPS", weight: 1.0 },
  { key: "config_score", label: "CONFIG", weight: 1.0 },
  { key: "description_score", label: "DESC", weight: 1.0 },
  { key: "behavior_score", label: "BEHAVIOR", weight: 0.8 },
];

function band(score: number): "good" | "moderate" | "poor" | "critical" {
  if (score >= 80) return "good";
  if (score >= 60) return "moderate";
  if (score >= 40) return "poor";
  return "critical";
}

function fmtDate(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" });
}

function isFresh(iso: string | null): boolean {
  if (!iso) return false;
  const age = Date.now() - new Date(iso).getTime();
  return age < 7 * 24 * 60 * 60 * 1000;
}

/** Inline SVG sparkline — no library. ~30 LOC including viewBox + polyline + last-point dot. */
function Sparkline({ history }: { history: ScoreHistoryPoint[] }) {
  const pts = history
    .filter((h): h is ScoreHistoryPoint & { score: number } => h.score != null)
    .slice(0, 30)
    .reverse();
  if (pts.length < 2) return null;
  const w = 280;
  const h = 32;
  const min = 0;
  const max = 100;
  const path = pts
    .map((p, i) => {
      const x = (i / (pts.length - 1)) * w;
      const y = h - ((p.score - min) / (max - min)) * h;
      return `${i === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
  const last = pts[pts.length - 1]!;
  const lastX = w;
  const lastY = h - ((last.score - min) / (max - min)) * h;
  return (
    <svg
      className="ts-sparkline"
      viewBox={`0 0 ${w} ${h}`}
      preserveAspectRatio="none"
      role="img"
      aria-label={`30-day score history: ${pts.map((p) => p.score).join(", ")}`}
    >
      <path d={path} fill="none" stroke="var(--accent)" strokeWidth="1.5" strokeLinejoin="round" strokeLinecap="round" />
      <circle cx={lastX} cy={lastY} r="2.5" fill="var(--accent)" />
    </svg>
  );
}

export default function TrustSignature(props: Props) {
  const {
    name, description, author, category, language, license, server_version,
    github_url, npm_package, pypi_package, connection_status, last_scanned_at,
    rules_version, score_detail, history,
  } = props;

  const total = score_detail?.total_score ?? null;
  const totalBand = total != null ? band(total) : "critical";
  const fresh = isFresh(last_scanned_at);

  return (
    <section className="frame trust-signature" aria-labelledby="ts-name">
      {/* Eyebrow */}
      <div className="ts-eyebrow eyebrow-mono">
        <span className="ts-eyebrow-tag">SECURITY ASSESSMENT</span>
        {rules_version && <span aria-hidden>·</span>}
        {rules_version && <span>RULES v{rules_version}</span>}
        <span aria-hidden>·</span>
        <span>{fmtDate(last_scanned_at)}</span>
        {fresh && <span className="pulse-dot" aria-label="Recently scanned" />}
      </div>

      <div className="ts-grid">
        {/* Left — identity */}
        <div className="ts-identity">
          <h1 id="ts-name" className="serif-display ts-name">
            {name}
            {connection_status === "success" && (
              <span className="sd-status-dot sd-status-connected" title="Connected" aria-label="Connection: success" role="img" />
            )}
            {(connection_status === "failed" || connection_status === "timeout") && (
              <span className="sd-status-dot sd-status-error" title="Connection error" aria-label="Connection: failed" role="img" />
            )}
          </h1>
          {description && <p className="ts-desc">{description}</p>}
          <div className="ts-meta">
            {author && <span className="sd-meta-chip">{author}</span>}
            {category && <span className="sd-meta-chip">{category}</span>}
            {language && <span className="sd-meta-chip">{language}</span>}
            {license && <span className="sd-meta-chip">{license}</span>}
            {server_version && <span className="sd-meta-chip">v{server_version}</span>}
          </div>
          <div className="ts-links">
            {github_url && (
              <a href={github_url} target="_blank" rel="noopener noreferrer" className="sd-link-btn">
                GitHub →
              </a>
            )}
            {npm_package && (
              <a href={`https://www.npmjs.com/package/${npm_package}`} target="_blank" rel="noopener noreferrer" className="sd-link-btn">
                npm →
              </a>
            )}
            {pypi_package && (
              <a href={`https://pypi.org/project/${pypi_package}`} target="_blank" rel="noopener noreferrer" className="sd-link-btn">
                PyPI →
              </a>
            )}
          </div>
        </div>

        {/* Right — score lineage */}
        <div className="ts-score">
          <div className="ts-score-headline">
            <span className={`ts-score-num serif-display ts-score-${totalBand}`}>
              {total != null ? total : "—"}
            </span>
            <span className="ts-score-denom">/100</span>
            <span className={`ts-score-band ts-score-band-${totalBand}`}>
              {totalBand.toUpperCase()}
            </span>
          </div>

          {score_detail && (
            <div className="ts-segments" role="group" aria-label="Score sub-components">
              {SUBSCORES.map((s) => {
                const v = score_detail[s.key] as number | undefined;
                if (v == null) return null;
                const segBand = band(v);
                return (
                  <div
                    key={s.key}
                    className={`ts-segment ts-segment-${segBand}`}
                    style={{ flex: s.weight }}
                    title={`${s.label}: ${v}/100`}
                  >
                    <span className="ts-segment-label">{s.label}</span>
                    <span className="ts-segment-val">{v}</span>
                  </div>
                );
              })}
            </div>
          )}

          {history.length > 1 && (
            <div className="ts-spark-wrap">
              <Sparkline history={history} />
              <span className="ts-spark-label eyebrow-mono">
                {history.length}-POINT HISTORY · {fmtDate(history[history.length - 1]?.recorded_at ?? null)} → {fmtDate(history[0]?.recorded_at ?? null)}
              </span>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
