import React from "react";
import type { Metadata } from "next";
import { notFound } from "next/navigation";
import ServerFindings from "@/components/ServerFindings";

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

interface Tool {
  name: string;
  description: string | null;
  capability_tags: string[];
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
  tools: Tool[];
  findings: Finding[];
}

// ── Data Fetching ─────────────────────────────────────────────────────────────

async function getServer(slug: string): Promise<ServerDetail | null> {
  try {
    const res = await fetch(
      `${API_URL}/api/v1/servers/${encodeURIComponent(slug)}`,
      { signal: AbortSignal.timeout(4000) }
    );
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
  if (!server) return { title: "Server Not Found" };
  const findCount = server.findings?.length ?? 0;
  const hasCritical = server.findings?.some((f) => f.severity === "critical");
  const verdictStr = findCount === 0
    ? "No issues detected."
    : hasCritical
      ? "Critical issues found."
      : `${findCount} finding${findCount !== 1 ? "s" : ""} detected.`;
  return {
    title: `${server.name} Security Report`,
    description: `Security analysis of ${server.name} MCP server. ${verdictStr} Scanned against 177 detection rules.`,
  };
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmtNum(n: number | null): string {
  if (n == null) return "\u2014";
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return n.toLocaleString();
}

function fmtDate(iso: string | null): string {
  if (!iso) return "\u2014";
  const d = new Date(iso);
  return d.toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
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

  const findings = server.findings ?? [];
  const tools = server.tools ?? [];

  return (
    <div className="sd-page">
      {/* Breadcrumb */}
      <nav className="sd-breadcrumb">
        <a href="/">Home</a>
        <span className="sd-bread-sep">/</span>
        <a href="/servers">Servers</a>
        <span className="sd-bread-sep">/</span>
        <span className="sd-bread-current">{server.name}</span>
      </nav>

      {/* ── Hero Section ───────────────────────────────────── */}
      <section className="sd-hero">
        <div className="sd-hero-left">
          <div className="sd-hero-title-row">
            <h1 className="sd-hero-name">{server.name}</h1>
            {server.connection_status === "connected" && (
              <span className="sd-status-dot sd-status-connected" title="Connected" />
            )}
            {server.connection_status === "error" && (
              <span className="sd-status-dot sd-status-error" title="Connection Error" />
            )}
          </div>
          {server.description && (
            <p className="sd-hero-desc">{server.description}</p>
          )}
          <div className="sd-meta-row">
            {server.author && (
              <span className="sd-meta-chip">
                <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
                  <circle cx="8" cy="5.5" r="2.5" />
                  <path d="M3 13c0-2.76 2.24-5 5-5s5 2.24 5 5" />
                </svg>
                {server.author}
              </span>
            )}
            {server.category && (
              <span className="sd-meta-chip">{server.category}</span>
            )}
            {server.language && (
              <span className="sd-meta-chip">{server.language}</span>
            )}
            {server.license && (
              <span className="sd-meta-chip">{server.license}</span>
            )}
            {server.server_version && (
              <span className="sd-meta-chip">v{server.server_version}</span>
            )}
          </div>
          <div className="sd-hero-links">
            {server.github_url && (
              <a href={server.github_url} target="_blank" rel="noopener noreferrer" className="sd-link-btn">
                <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor">
                  <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z" />
                </svg>
                GitHub
              </a>
            )}
            {server.npm_package && (
              <a href={`https://www.npmjs.com/package/${server.npm_package}`} target="_blank" rel="noopener noreferrer" className="sd-link-btn">
                npm
              </a>
            )}
            {server.pypi_package && (
              <a href={`https://pypi.org/project/${server.pypi_package}`} target="_blank" rel="noopener noreferrer" className="sd-link-btn">
                PyPI
              </a>
            )}
          </div>
        </div>
      </section>

      {/* ── Quick Stats ────────────────────────────────────── */}
      <section className="sd-quick-stats">
        <div className="sd-qs-item">
          <span className="sd-qs-val">{server.tool_count}</span>
          <span className="sd-qs-label">Tools</span>
        </div>
        <div className="sd-qs-item">
          <span className="sd-qs-val">{findings.length}</span>
          <span className="sd-qs-label">Findings</span>
        </div>
        <div className="sd-qs-item">
          <span className="sd-qs-val">{fmtNum(server.github_stars)}</span>
          <span className="sd-qs-label">Stars</span>
        </div>
        <div className="sd-qs-item">
          <span className="sd-qs-val">{fmtNum(server.npm_downloads)}</span>
          <span className="sd-qs-label">Downloads</span>
        </div>
        <div className="sd-qs-item">
          <span className="sd-qs-val sd-qs-val-sm">{fmtDate(server.last_scanned_at)}</span>
          <span className="sd-qs-label">Last Scanned</span>
        </div>
      </section>

      {/* ── Verdict + Findings + Tools (interactive client component) ── */}
      <ServerFindings
        findings={findings}
        tools={tools}
        lastScannedAt={server.last_scanned_at}
      />
    </div>
  );
}
