import React from "react";
import type { Metadata } from "next";
import { notFound } from "next/navigation";
import CategoryDeepDivePanel from "@/components/CategoryDeepDivePanel";
import type { CddFinding } from "@/components/cdd-data";
import { RULE_NAMES, RULE_SEVERITIES } from "@/components/cdd-data";

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
  last_commit: string | null;
  last_scanned_at: string | null;
  endpoint_url: string | null;
  connection_status: string | null;
  server_version: string | null;
  tool_count: number;
  tools: Tool[];
  findings: Finding[];
  owasp_coverage?: Record<string, boolean>;
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

const SEV_ORDER = ["critical", "high", "medium", "low", "informational"] as const;

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

  // Group findings by severity
  const findingsBySev: Record<string, Finding[]> = {};
  for (const f of findings) {
    if (!findingsBySev[f.severity]) findingsBySev[f.severity] = [];
    findingsBySev[f.severity].push(f);
  }

  const sevCounts = SEV_ORDER.map((s) => ({
    sev: s,
    count: findingsBySev[s]?.length ?? 0,
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
          <div className="sd-hero-title-row">
            <h1 className="sd-hero-name">{server.name}</h1>
            {server.connection_status === "connected" && (
              <span className="sd-status-dot sd-status-connected" title="Connected" aria-label="Connection status: connected" role="img" />
            )}
            {server.connection_status === "error" && (
              <span className="sd-status-dot sd-status-error" title="Connection Error" aria-label="Connection status: error" role="img" />
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
      </section>

      {/* ── Quick Stats ────────────────────────────────────── */}
      <section className="sd-quick-stats">
        <div className="sd-qs-item">
          <span className="sd-qs-val">{server.tool_count}</span>
          <span className="sd-qs-label">Tools</span>
        </div>
        <div className="sd-qs-item">
          <span className="sd-qs-val" style={findings.length > 0 ? { color: "var(--critical)" } : { color: "var(--good)" }}>
            {findings.length}
          </span>
          <span className="sd-qs-label">Findings</span>
        </div>
        {server.github_stars != null && (
          <div className="sd-qs-item">
            <span className="sd-qs-val">{fmtNum(server.github_stars)}</span>
            <span className="sd-qs-label">Stars</span>
          </div>
        )}
        {server.npm_downloads != null && (
          <div className="sd-qs-item">
            <span className="sd-qs-val">{fmtNum(server.npm_downloads)}</span>
            <span className="sd-qs-label">Downloads</span>
          </div>
        )}
        <div className="sd-qs-item">
          <span className="sd-qs-val sd-qs-val-sm">{fmtDate(server.last_scanned_at)}</span>
          <span className="sd-qs-label">Last Scanned</span>
        </div>
      </section>

      {/* ── Verdict Banner ──────────────────────────────────── */}
      <section className="sd-verdict">
        {findings.length === 0 && server.last_scanned_at ? (
          <div className="sd-verdict-clean">
            <span className="sd-verdict-icon">&#10003;</span>
            <span>No security findings detected across 177 detection rules.</span>
          </div>
        ) : findings.length > 0 ? (
          <div className="sd-verdict-alert">
            <span className="sd-verdict-icon">&#9888;</span>
            <span>
              {sevCounts.filter(s => s.count > 0).map(s => `${s.count} ${s.sev}`).join(" \u00B7 ")}
              {" "}finding{findings.length !== 1 ? "s" : ""} detected
            </span>
          </div>
        ) : null}
      </section>

      {/* ── Section Navigation ─────────────────────────────── */}
      <nav className="sd-section-nav">
        {server.owasp_coverage && Object.keys(server.owasp_coverage).length > 0 && (
          <a href="#owasp">OWASP Coverage</a>
        )}
        {findings.length > 0 && (
          <a href="#findings">Findings ({findings.length})</a>
        )}
        {tools.length > 0 && (
          <a href="#tools">Tools ({tools.length})</a>
        )}
        <a href="#deep-dive">Category Deep Dive</a>
      </nav>

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

      {/* ── Findings ────────────────────────────────────────── */}
      {findings.length > 0 && (
        <section id="findings" className="sd-section">
          <h2 className="sd-section-title">
            Findings
            <span className="sd-section-count">{findings.length}</span>
          </h2>

          <div className="sd-sev-summary">
            {sevCounts.filter(({ count }) => count > 0).map(({ sev, count }) => (
              <div key={sev} className={`sd-sev-chip sd-sev-chip-${sev}`}>
                <span className="sd-sev-chip-count">{count}</span>
                <span className="sd-sev-chip-label">{sev}</span>
              </div>
            ))}
          </div>

          <div className="sd-findings-list">
            {SEV_ORDER.map((sev) => {
              const group = findingsBySev[sev] ?? [];
              if (group.length === 0) return null;
              return (
                <div key={sev} className="sd-findings-group">
                  <h3 className={`sd-findings-group-title sd-sev-${sev}`}>
                    {sev.charAt(0).toUpperCase() + sev.slice(1)}
                    <span className="sd-findings-group-count">{group.length}</span>
                  </h3>
                  {group.map((f) => (
                    <div
                      key={f.id}
                      className={`sd-finding finding-${f.severity}`}
                    >
                      <div className="sd-finding-header">
                        <span className={`sev-badge sev-${f.severity}`}>
                          {f.severity}
                        </span>
                        <span className="sd-finding-rule">{f.rule_id}</span>
                        <span className="sd-finding-name">
                          {RULE_NAMES[f.rule_id] ?? f.rule_id}
                        </span>
                        {f.owasp_category && (
                          <span className="sd-finding-owasp">{f.owasp_category}</span>
                        )}
                        {f.mitre_technique && (
                          <span className="sd-finding-mitre">{f.mitre_technique}</span>
                        )}
                      </div>
                      <div className="sd-finding-evidence">{f.evidence}</div>
                      {f.remediation && (
                        <div className="sd-finding-fix">{f.remediation}</div>
                      )}
                    </div>
                  ))}
                </div>
              );
            })}
          </div>
        </section>
      )}

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
        <CategoryDeepDivePanel findings={cddFindings} />
      </div>
    </div>
  );
}
