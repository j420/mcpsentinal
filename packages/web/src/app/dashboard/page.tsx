import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Ecosystem Dashboard",
  description:
    "Live security intelligence across the entire MCP ecosystem — score distribution, OWASP coverage, category risk breakdown, and top findings.",
};

export const dynamic = "force-dynamic";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3100";

// ── Types ─────────────────────────────────────────────────────────────────────

interface EcosystemStats {
  total_servers: number;
  total_scanned: number;
  average_score: number;
  category_breakdown: Record<string, number>;
  severity_breakdown: Record<string, number>;
  score_distribution: Array<{ range: string; count: number }>;
}

interface Server {
  id: string;
  name: string;
  slug: string;
  latest_score: number | null;
  category: string | null;
  findings_count?: number;
}

// ── Data ──────────────────────────────────────────────────────────────────────

async function getStats(): Promise<EcosystemStats | null> {
  try {
    const res = await fetch(`${API_URL}/api/v1/ecosystem/stats`, {
      signal: AbortSignal.timeout(4000),
    });
    if (!res.ok) return null;
    const data = await res.json();
    return data.data ?? null;
  } catch {
    return null;
  }
}

async function getAtRiskServers(): Promise<Server[]> {
  try {
    const params = new URLSearchParams({
      sort: "score",
      order: "asc",
      limit: "10",
      max_score: "40",
    });
    const res = await fetch(`${API_URL}/api/v1/servers?${params}`, {
      signal: AbortSignal.timeout(4000),
    });
    if (!res.ok) return [];
    const data = await res.json();
    return data.data ?? [];
  } catch {
    return [];
  }
}

async function getTopServers(): Promise<Server[]> {
  try {
    const params = new URLSearchParams({
      sort: "score",
      order: "desc",
      limit: "10",
      min_score: "80",
    });
    const res = await fetch(`${API_URL}/api/v1/servers?${params}`, {
      signal: AbortSignal.timeout(4000),
    });
    if (!res.ok) return [];
    const data = await res.json();
    return data.data ?? [];
  } catch {
    return [];
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function scoreColor(s: number | null): string {
  if (s === null) return "var(--text-3)";
  if (s >= 80) return "var(--good)";
  if (s >= 60) return "var(--moderate)";
  if (s >= 40) return "var(--poor)";
  return "var(--critical)";
}

function ScoreBadge({ score }: { score: number | null }) {
  const cls =
    score === null
      ? "score-unscanned"
      : score >= 80
        ? "score-good"
        : score >= 60
          ? "score-moderate"
          : score >= 40
            ? "score-poor"
            : "score-critical";
  return (
    <span className={`score-badge ${cls}`}>
      {score === null ? "—" : score}
    </span>
  );
}

const OWASP_LIST = [
  { id: "MCP01", name: "Prompt Injection" },
  { id: "MCP02", name: "Tool Poisoning" },
  { id: "MCP03", name: "Command Injection" },
  { id: "MCP04", name: "Data Exfiltration" },
  { id: "MCP05", name: "Privilege Escalation" },
  { id: "MCP06", name: "Excessive Permissions" },
  { id: "MCP07", name: "Insecure Configuration" },
  { id: "MCP08", name: "Dependency Vulnerabilities" },
  { id: "MCP09", name: "Logging & Monitoring" },
  { id: "MCP10", name: "Supply Chain" },
];

const RULE_CATEGORIES = [
  { code: "A", name: "Description Analysis", count: 9 },
  { code: "B", name: "Schema Analysis", count: 7 },
  { code: "C", name: "Code Analysis", count: 16 },
  { code: "D", name: "Dependency Analysis", count: 7 },
  { code: "E", name: "Behavioral Analysis", count: 4 },
  { code: "F", name: "Ecosystem Context", count: 7 },
  { code: "G", name: "Adversarial AI", count: 7 },
  { code: "H", name: "2026 Attack Surface", count: 3 },
  { code: "I", name: "Protocol Surface", count: 16 },
  { code: "J", name: "2026 Threat Intelligence", count: 7 },
  { code: "K", name: "Compliance & Governance", count: 20 },
];

const SEV_CONFIG = {
  critical: { label: "Critical", color: "var(--sev-critical)" },
  high: { label: "High", color: "var(--sev-high)" },
  medium: { label: "Medium", color: "var(--sev-medium)" },
  low: { label: "Low", color: "var(--sev-low)" },
  informational: { label: "Info", color: "var(--sev-info)" },
};

// ── Page ──────────────────────────────────────────────────────────────────────

export default async function DashboardPage() {
  const [stats, atRisk, topServers] = await Promise.all([
    getStats(),
    getAtRiskServers(),
    getTopServers(),
  ]);

  const scanCoverage = stats
    ? Math.round((stats.total_scanned / Math.max(stats.total_servers, 1)) * 100)
    : 0;

  const avgColor =
    stats && stats.average_score >= 80
      ? "var(--good)"
      : stats && stats.average_score >= 60
        ? "var(--moderate)"
        : stats && stats.average_score >= 40
          ? "var(--poor)"
          : "var(--critical)";

  const totalFindings = stats
    ? Object.values(stats.severity_breakdown).reduce((a, b) => a + b, 0)
    : 0;

  const maxDistCount = stats
    ? Math.max(...(stats.score_distribution || []).map((d) => d.count), 1)
    : 1;

  const maxCatCount = stats
    ? Math.max(...Object.values(stats.category_breakdown || {}), 1)
    : 1;

  const maxSevCount = totalFindings > 0
    ? Math.max(...Object.values(stats?.severity_breakdown || {}), 1)
    : 1;

  const apiDown = !stats && atRisk.length === 0 && topServers.length === 0;

  return (
    <>
      {/* ── API warning ──────────────────────────────── */}
      {apiDown && (
        <div role="alert" className="api-alert">
          <span className="api-alert-icon">!</span>
          <span>Unable to reach the API. Dashboard data is unavailable.</span>
        </div>
      )}

      {/* ── Page header ─────────────────────────────── */}
      <section className="dash-header">
        <div className="hero-eyebrow">Live Data</div>
        <h1 className="dash-title">Ecosystem Dashboard</h1>
        <p className="dash-sub">
          Aggregated security posture across every MCP server we&apos;ve discovered.
          Updates every 5 minutes.
        </p>
      </section>

      {/* ── KPI strip ───────────────────────────────── */}
      <section className="stats-grid">
        <div className="stat-card">
          <span className="stat-value">
            {stats?.total_servers.toLocaleString() ?? "\u2014"}
          </span>
          <span className="stat-label">Total Servers</span>
        </div>
        <div className="stat-card">
          <span className="stat-value">
            {stats?.total_scanned.toLocaleString() ?? "\u2014"}
            <span className="stat-value-sub"> ({scanCoverage}%)</span>
          </span>
          <span className="stat-label">Scanned</span>
        </div>
        <div className="stat-card">
          <span className="stat-value" style={{ color: avgColor }}>
            {stats?.average_score ?? "\u2014"}
            <span className="stat-value-denom">/100</span>
          </span>
          <span className="stat-label">Avg Security Score</span>
        </div>
        <div className="stat-card">
          <span className="stat-value" style={{ color: "var(--critical)" }}>
            {(stats?.severity_breakdown?.["critical"] ?? 0).toLocaleString()}
          </span>
          <span className="stat-label">Critical Findings</span>
        </div>
      </section>

      {/* ── Two-column layout ───────────────────────── */}
      <div className="dash-two-col">
        {/* Score distribution */}
        <div className="card">
          <h2 className="section-title">Score Distribution</h2>
          {stats?.score_distribution && stats.score_distribution.length > 0 ? (
            <div>
              {stats.score_distribution.map((bucket) => {
                const pct = Math.round((bucket.count / maxDistCount) * 100);
                const rangeLow = parseInt(bucket.range.split("-")[0] || "0", 10);
                const barColor =
                  rangeLow >= 80
                    ? "var(--good)"
                    : rangeLow >= 60
                      ? "var(--moderate)"
                      : rangeLow >= 40
                        ? "var(--poor)"
                        : "var(--critical)";
                return (
                  <div key={bucket.range} className="dist-bar-row">
                    <span className="dist-bar-label">{bucket.range}</span>
                    <div className="dist-bar-bg">
                      <div
                        className="dist-bar-fill"
                        style={{ width: `${pct}%`, background: barColor }}
                      />
                    </div>
                    <span className="dist-bar-count">
                      {bucket.count.toLocaleString()}
                    </span>
                  </div>
                );
              })}
            </div>
          ) : (
            <p className="text-muted-sm">
              No distribution data yet &mdash; run a scan first.
            </p>
          )}
        </div>

        {/* Findings by severity */}
        <div className="card">
          <h2 className="section-title">
            Findings by Severity{" "}
            <span className="count">{totalFindings.toLocaleString()}</span>
          </h2>
          {totalFindings > 0 ? (
            <div>
              {Object.entries(SEV_CONFIG).map(([sev, cfg]) => {
                const count = stats?.severity_breakdown?.[sev] ?? 0;
                const pct = Math.round((count / maxSevCount) * 100);
                return (
                  <div key={sev} className="dist-bar-row">
                    <span className="dist-bar-label" style={{ color: cfg.color }}>
                      {cfg.label}
                    </span>
                    <div className="dist-bar-bg">
                      <div
                        className="dist-bar-fill"
                        style={{ width: `${pct}%`, background: cfg.color, opacity: 0.7 }}
                      />
                    </div>
                    <span className="dist-bar-count">{count.toLocaleString()}</span>
                  </div>
                );
              })}
            </div>
          ) : (
            <p className="text-muted-sm">No finding data yet.</p>
          )}
        </div>
      </div>

      {/* ── Category breakdown ──────────────────────── */}
      <div className="card section-gap">
        <h2 className="section-title">Category Breakdown</h2>
        {stats?.category_breakdown && Object.keys(stats.category_breakdown).length > 0 ? (
          <div className="dash-auto-grid">
            {Object.entries(stats.category_breakdown)
              .sort((a, b) => b[1] - a[1])
              .map(([cat, count]) => {
                const pct = Math.round((count / maxCatCount) * 100);
                return (
                  <a key={cat} href={`/?category=${cat}`} style={{ textDecoration: "none" }}>
                    <div className="card-sm card-hover cat-card-inner">
                      <div className="cat-card-row">
                        <span className="cat-card-name">{cat}</span>
                        <span className="cat-card-count">{count.toLocaleString()}</span>
                      </div>
                      <div className="dist-bar-bg dist-bar-thin">
                        <div
                          className="dist-bar-fill"
                          style={{ width: `${pct}%`, background: "var(--accent)", opacity: 0.6 }}
                        />
                      </div>
                    </div>
                  </a>
                );
              })}
          </div>
        ) : (
          <p className="text-muted-sm">No category data yet.</p>
        )}
      </div>

      {/* ── At-risk + Top-scored ────────────────────── */}
      <div className="dash-two-col">
        {/* At-risk servers */}
        <div className="card">
          <h2 className="section-title">
            Highest Risk
            <span className="count">{atRisk.length}</span>
          </h2>
          {atRisk.length === 0 ? (
            <p className="text-muted-sm">No critical-risk servers found.</p>
          ) : (
            <div className="server-list">
              {atRisk.map((server) => (
                <div key={server.id} className="server-row-hover">
                  <div>
                    <a href={`/server/${server.slug}`} className="server-row-link">
                      {server.name}
                    </a>
                    {server.category && (
                      <span className="server-row-cat">{server.category}</span>
                    )}
                  </div>
                  <ScoreBadge score={server.latest_score} />
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Top-scored servers */}
        <div className="card">
          <h2 className="section-title">
            Top Scored
            <span className="count">{topServers.length}</span>
          </h2>
          {topServers.length === 0 ? (
            <p className="text-muted-sm">No servers with high scores yet.</p>
          ) : (
            <div className="server-list">
              {topServers.map((server) => (
                <div key={server.id} className="server-row-hover">
                  <div>
                    <a href={`/server/${server.slug}`} className="server-row-link">
                      {server.name}
                    </a>
                    {server.category && (
                      <span className="server-row-cat">{server.category}</span>
                    )}
                  </div>
                  <ScoreBadge score={server.latest_score} />
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* ── Scan coverage bar ─────────────────────── */}
      {stats && (
        <div className="card section-gap">
          <h2 className="section-title">Scan Coverage</h2>
          <div className="scan-coverage-row">
            <div className="dist-bar-bg" style={{ flex: 1, height: "8px" }}>
              <div
                className="dist-bar-fill"
                style={{
                  width: `${scanCoverage}%`,
                  background: scanCoverage >= 80 ? "var(--good)" : scanCoverage >= 50 ? "var(--moderate)" : "var(--poor)",
                }}
              />
            </div>
            <span className="scan-coverage-label">
              {stats.total_scanned.toLocaleString()} / {stats.total_servers.toLocaleString()} scanned ({scanCoverage}%)
            </span>
          </div>
          {stats.total_servers - stats.total_scanned > 0 && (
            <p className="scan-coverage-note">
              {(stats.total_servers - stats.total_scanned).toLocaleString()} servers awaiting scan
            </p>
          )}
        </div>
      )}

      {/* ── Detection rule categories ─────────────────── */}
      <div className="card section-gap">
        <h2 className="section-title">
          Detection Rules
          <span className="count">103</span>
        </h2>
        <p className="section-desc">
          150+ rules across 11 categories &mdash; every server is evaluated against all applicable rules.
        </p>
        <div className="dash-auto-grid-sm">
          {RULE_CATEGORIES.map((cat) => (
            <div key={cat.code} className="card-sm rule-cat-card">
              <span className="rule-cat-code">{cat.code}</span>
              <span className="rule-cat-name">{cat.name}</span>
              <span className="rule-cat-count">{cat.count}</span>
            </div>
          ))}
        </div>
      </div>

      {/* ── OWASP MCP Top 10 overview ───────────────── */}
      <div className="card section-gap">
        <h2 className="section-title">OWASP MCP Top 10 Coverage</h2>
        <p className="section-desc-lg">
          Detection rules mapped to all 10 OWASP MCP categories. Every server
          is evaluated against each category on every scan.
        </p>
        <div className="dash-auto-grid-xs">
          {OWASP_LIST.map((owasp) => (
            <div key={owasp.id} className="card-sm owasp-card">
              <span className="owasp-card-id">{owasp.id}</span>
              <span className="owasp-card-name">{owasp.name}</span>
            </div>
          ))}
        </div>
      </div>
    </>
  );
}
