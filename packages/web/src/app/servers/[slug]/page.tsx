import React from "react";
import type { Metadata } from "next";
import { notFound } from "next/navigation";
import CategoryDeepDivePanel from "@/components/CategoryDeepDivePanel";
import type { CddFinding } from "@/components/cdd-data";
import ServerProfileCard from "@/components/ServerProfileCard";
import type { ServerProfileData } from "@/components/ServerProfileCard";
import AttackChainCard from "@/components/AttackChainCard";
import type { AttackChainItem } from "@/components/AttackChainCard";

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
  /** Phase 1: per-finding confidence score (0.0–1.0). Absent on pre-Phase-1 data. */
  confidence?: number;
  /** Phase 1: structured evidence chain proving the finding. Absent on pre-Phase-1 data. */
  evidence_chain?: Record<string, unknown> | null;
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
  last_commit: string | null;
  last_scanned_at: string | null;
  endpoint_url: string | null;
  connection_status: string | null;
  server_version: string | null;
  tool_count: number;
  tools: Tool[];
  findings: Finding[];
  owasp_coverage?: Record<string, boolean>;
  /** Phase 1: server capability profile. Absent until API serves Phase 1 data. */
  profile?: ServerProfileData | null;
  /** Attack chains involving this server. Absent until API serves attack chain data. */
  attack_chains?: AttackChainItem[] | null;
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
  return {
    title: `${server.name} Security Report`,
    description: `Security analysis of ${server.name} MCP server. ${findCount} finding${findCount !== 1 ? "s" : ""} detected across 177 detection rules.`,
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

const OWASP_NAMES: Record<string, string> = {
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
  const cddFindings: CddFinding[] = findings.map((f) => ({
    rule_id: f.rule_id,
    severity: f.severity,
  }));

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
            {server.connection_status === "success" && (
              <span className="sd-status-dot sd-status-connected" title="Connected" aria-label="Connection status: success" role="img" />
            )}
            {(server.connection_status === "failed" || server.connection_status === "timeout") && (
              <span className="sd-status-dot sd-status-error" title="Connection Error" aria-label="Connection status: failed" role="img" />
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

        <div className="sd-hero-stats">
          <div className="sd-hero-stat">
            <span className="sd-hero-stat-val">{server.tool_count}</span>
            <span className="sd-hero-stat-label">Tools</span>
          </div>
          <div className="sd-hero-stat">
            <span className="sd-hero-stat-val" style={findings.length > 0 ? { color: "var(--critical)" } : { color: "var(--good)" }}>
              {findings.length}
            </span>
            <span className="sd-hero-stat-label">Findings</span>
          </div>
          {server.github_stars != null && (
            <div className="sd-hero-stat">
              <span className="sd-hero-stat-val">{fmtNum(server.github_stars)}</span>
              <span className="sd-hero-stat-label">Stars</span>
            </div>
          )}
          {server.npm_downloads != null && (
            <div className="sd-hero-stat">
              <span className="sd-hero-stat-val">{fmtNum(server.npm_downloads)}</span>
              <span className="sd-hero-stat-label">Downloads</span>
            </div>
          )}
          <div className="sd-hero-stat">
            <span className="sd-hero-stat-val sd-hero-stat-val-sm">{fmtDate(server.last_scanned_at)}</span>
            <span className="sd-hero-stat-label">Last Scanned</span>
          </div>
        </div>
      </section>

      {/* ── OWASP Coverage ─────────────────────────────────── */}
      {server.owasp_coverage && Object.keys(server.owasp_coverage).length > 0 && (
        <section id="owasp" className="sd-section">
          <h2 className="sd-section-title">
            OWASP MCP Top 10 Coverage
          </h2>
          <p className="sd-section-sub">Pass = no findings in this category. Fail = issues detected.</p>
          <div className="sd-owasp-grid">
            {Object.entries(server.owasp_coverage).map(([id, clean]) => (
              <div
                key={id}
                className={`sd-owasp-item ${clean ? "sd-owasp-clean" : "sd-owasp-dirty"}`}
              >
                <span className="sd-owasp-indicator" />
                <span className="sd-owasp-id">{id}</span>
                <span className="sd-owasp-name">{OWASP_NAMES[id] ?? id}</span>
                <span className="sd-owasp-status">{clean ? "Pass" : "Fail"}</span>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* ── Server Profile (Phase 1 — renders nothing if profile absent) ── */}
      <ServerProfileCard profile={server.profile ?? null} />

      {/* ── Attack Chains (renders nothing if no chains) ──── */}
      <AttackChainCard
        chains={server.attack_chains ?? null}
        currentServerId={server.id}
      />

      {/* ── Tools ──────────────────────────────────────────── */}
      {tools.length > 0 && (
        <section id="tools" className="sd-section">
          <h2 className="sd-section-title">
            Tools
            <span className="sd-section-count">{tools.length}</span>
          </h2>
          <div className="sd-tools-grid">
            {tools.map((tool) => (
              <div key={tool.name} className="sd-tool">
                <div className="sd-tool-name">{tool.name}</div>
                {tool.description && (
                  <div className="sd-tool-desc">{tool.description}</div>
                )}
                {tool.capability_tags.length > 0 && (
                  <div className="sd-tool-caps">
                    {tool.capability_tags.map((tag) => (
                      <span key={tag} className={`cap-tag cap-${tag}`}>
                        {tag.replace(/-/g, " ")}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </section>
      )}

      {/* ── Category Deep Dive ─────────────────────────────── */}
      <div id="deep-dive">
        <CategoryDeepDivePanel findings={cddFindings} fullFindings={findings} />
      </div>

    </div>
  );
}
