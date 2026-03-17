import React from "react";
import type { Metadata } from "next";
import { notFound } from "next/navigation";
import CategoryDeepDivePanel from "@/components/CategoryDeepDivePanel";
import type { CddFinding } from "@/components/cdd-data";

export const dynamic = "force-dynamic";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3100";

// ── Types ─────────────────────────────────────────────────────────────────────

interface Finding {
  id: string;
  rule_id: string;
  severity: "critical" | "high" | "medium" | "low" | "informational";
  evidence: string;
  remediation: string;
  owasp_category: string | null;
  mitre_technique: string | null;
}

interface ScoreDetail {
  total_score: number;
  code_score: number;
  deps_score: number;
  config_score: number;
  description_score: number;
  behavior_score: number;
  owasp_coverage: Record<string, boolean>;
}

interface ServerDetail {
  id: string;
  name: string;
  slug: string;
  description: string | null;
  author: string | null;
  category: string | null;
  language: string | null;
  license: string | null;
  github_url: string | null;
  npm_package: string | null;
  pypi_package: string | null;
  github_stars: number | null;
  npm_downloads: number | null;
  latest_score: number | null;
  last_commit: string | null;
  last_scanned_at: string | null;
  endpoint_url: string | null;
  connection_status: string | null;
  server_version: string | null;
  tool_count: number;
  tools: { name: string; description: string | null; capability_tags: string[] }[];
  findings: Finding[];
  score_detail?: ScoreDetail;
}

// ── Data Fetching ─────────────────────────────────────────────────────────────

async function getServer(slug: string): Promise<ServerDetail | null> {
  try {
    const res = await fetch(`${API_URL}/api/v1/servers/${encodeURIComponent(slug)}`, {
      signal: AbortSignal.timeout(4000),
    });
    if (!res.ok) return null;
    const data = await res.json();
    return data.data ?? null;
  } catch {
    return null;
  }
}

// ── SEO Metadata ──────────────────────────────────────────────────────────────

export async function generateMetadata({
  params,
}: {
  params: Promise<{ slug: string }>;
}): Promise<Metadata> {
  const { slug } = await params;
  const server = await getServer(slug);
  if (!server) {
    return { title: "Server Not Found" };
  }
  const scoreStr =
    server.latest_score !== null
      ? `Score: ${server.latest_score}/100.`
      : "Not yet scanned.";
  const findCount = server.findings?.length ?? 0;
  return {
    title: `${server.name} Security Report`,
    description: `Security analysis of ${server.name} MCP server. ${scoreStr} ${findCount} finding${findCount !== 1 ? "s" : ""} detected across 103 security rules.`,
  };
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function scoreColor(s: number | null): string {
  if (s === null) return "var(--text-3)";
  if (s >= 80) return "var(--good)";
  if (s >= 60) return "var(--moderate)";
  if (s >= 40) return "var(--poor)";
  return "var(--critical)";
}

function scoreLabel(s: number | null): string {
  if (s === null) return "Unscanned";
  if (s >= 80) return "Good";
  if (s >= 60) return "Moderate";
  if (s >= 40) return "Poor";
  return "Critical";
}

function fmtNum(n: number | null): string {
  if (n == null) return "\u2014";
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return n.toLocaleString();
}

function fmtDate(iso: string | null): string {
  if (!iso) return "\u2014";
  const d = new Date(iso);
  return d.toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" });
}

// ── Score Ring (SVG, server-rendered) ─────────────────────────────────────────

function ScoreRing({ score }: { score: number | null }) {
  const r = 36;
  const circ = 2 * Math.PI * r;
  const pct = score !== null ? score / 100 : 0;
  const offset = circ * (1 - pct);
  const color = scoreColor(score);

  return (
    <div className="score-ring-wrap">
      <svg
        width="100"
        height="100"
        viewBox="0 0 100 100"
        className="score-ring-svg"
        aria-hidden="true"
      >
        <circle cx="50" cy="50" r={r} fill="none" stroke="var(--surface-3)" strokeWidth="8" />
        {score !== null && (
          <circle
            cx="50"
            cy="50"
            r={r}
            fill="none"
            stroke={color}
            strokeWidth="8"
            strokeLinecap="round"
            strokeDasharray={circ}
            strokeDashoffset={offset}
            className="score-ring-arc"
          />
        )}
      </svg>
      <div className="score-ring-center">
        <span
          className={`score-ring-number ${score !== null ? "score-ring-number-value" : "score-ring-number-empty"}`}
          style={{ color }}
        >
          {score !== null ? score : "\u2014"}
        </span>
        {score !== null && (
          <span className="score-ring-denom">/ 100</span>
        )}
      </div>
    </div>
  );
}

// ── Sub-Score Bar ─────────────────────────────────────────────────────────────

function SubScoreBar({ label, value }: { label: string; value: number | undefined }) {
  const v = value ?? 100;
  const color =
    v >= 80 ? "var(--good)" : v >= 60 ? "var(--moderate)" : v >= 40 ? "var(--poor)" : "var(--critical)";
  return (
    <div className="subscore-row">
      <span className="subscore-label">{label}</span>
      <div className="subscore-bar-bg">
        <div className="subscore-bar-fill" style={{ width: `${v}%`, background: color }} />
      </div>
      <span className="subscore-val">{v}</span>
    </div>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default async function ServerDetailPage({
  params,
}: {
  params: Promise<{ slug: string }>;
}) {
  const { slug } = await params;
  const server = await getServer(slug);

  if (!server) return notFound();

  const sd = server.score_detail;
  const findings = server.findings ?? [];
  const cddFindings: CddFinding[] = findings.map((f) => ({
    rule_id: f.rule_id,
    severity: f.severity,
  }));

  const connectionIcon =
    server.connection_status === "connected"
      ? "\u2705"
      : server.connection_status === "error"
        ? "\u274C"
        : "\u2014";

  return (
    <main className="detail-layout">
      {/* ── Server Header ─────────────────────────────────────────────── */}
      <section className="server-header">
        <div className="server-header-top">
          <div className="score-ring-card">
            <ScoreRing score={server.latest_score} />
            <span className="score-ring-label" style={{ color: scoreColor(server.latest_score) }}>
              {scoreLabel(server.latest_score)}
            </span>
          </div>

          <div className="server-header-info">
            <h1 className="server-name">{server.name}</h1>
            {server.description && (
              <p className="server-description">{server.description}</p>
            )}
            <div className="server-meta-grid">
              {server.author && <MetaItem label="Author" value={server.author} />}
              {server.category && <MetaItem label="Category" value={server.category} />}
              {server.language && <MetaItem label="Language" value={server.language} />}
              <MetaItem label="Stars" value={fmtNum(server.github_stars)} />
              <MetaItem label="Downloads" value={fmtNum(server.npm_downloads)} />
              <MetaItem label="Last Scanned" value={fmtDate(server.last_scanned_at)} />
              <MetaItem label="Connection" value={`${connectionIcon} ${server.connection_status ?? "unknown"}`} />
              {server.server_version && <MetaItem label="Version" value={server.server_version} />}
              <MetaItem label="Tools" value={String(server.tool_count)} />
              <MetaItem label="Findings" value={String(findings.length)} />
            </div>
            {server.github_url && (
              <a
                href={server.github_url}
                target="_blank"
                rel="noopener noreferrer"
                className="server-github-link"
              >
                View on GitHub
              </a>
            )}
          </div>
        </div>
      </section>

      {/* ── Score Summary ─────────────────────────────────────────────── */}
      {sd ? (
        <section className="score-summary-section">
          <h2 className="section-title">Score Breakdown</h2>
          <div className="subscore-list">
            <SubScoreBar label="Code" value={sd.code_score} />
            <SubScoreBar label="Dependencies" value={sd.deps_score} />
            <SubScoreBar label="Config" value={sd.config_score} />
            <SubScoreBar label="Description" value={sd.description_score} />
            <SubScoreBar label="Behavior" value={sd.behavior_score} />
          </div>
        </section>
      ) : (
        <section className="score-summary-section">
          <h2 className="section-title">Score Breakdown</h2>
          <p className="empty-state">Not yet scanned. Score will appear after the first scan.</p>
        </section>
      )}

      {/* ── Category Deep Dive ────────────────────────────────────────── */}
      <CategoryDeepDivePanel findings={cddFindings} />
    </main>
  );
}

// ── Small helper component ────────────────────────────────────────────────────

function MetaItem({ label, value }: { label: string; value: string }) {
  return (
    <div className="meta-item">
      <span className="meta-label">{label}</span>
      <span className="meta-value">{value}</span>
    </div>
  );
}
