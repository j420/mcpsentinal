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
        <div
          role="alert"
          style={{
            background: "var(--surface-2)",
            border: "1px solid var(--poor)",
            borderRadius: "8px",
            padding: "12px 16px",
            margin: "var(--s4) 0",
            display: "flex",
            alignItems: "center",
            gap: "var(--s2)",
            fontSize: "13px",
            color: "var(--text-2)",
          }}
        >
          <span style={{ color: "var(--poor)", fontWeight: 700, fontSize: "16px", lineHeight: 1 }}>!</span>
          <span>
            Unable to reach the API. Dashboard data is unavailable.
          </span>
        </div>
      )}

      {/* ── Page header ─────────────────────────────── */}
      <section style={{ paddingTop: "var(--s10)", marginBottom: "var(--s8)" }}>
        <div className="hero-eyebrow" style={{ display: "inline-flex" }}>
          Live Data
        </div>
        <h1
          style={{
            fontSize: "clamp(26px, 4vw, 40px)",
            fontWeight: 700,
            letterSpacing: "-0.03em",
            margin: "var(--s3) 0 var(--s2)",
          }}
        >
          Ecosystem Dashboard
        </h1>
        <p style={{ color: "var(--text-2)", fontSize: "16px", maxWidth: "540px" }}>
          Aggregated security posture across every MCP server we&apos;ve discovered.
          Updates every 5 minutes.
        </p>
      </section>

      {/* ── KPI strip ───────────────────────────────── */}
      <section className="stats-grid" style={{ marginBottom: "var(--s8)" }}>
        <div className="stat-card">
          <span className="stat-value">
            {stats?.total_servers.toLocaleString() ?? "—"}
          </span>
          <span className="stat-label">Total Servers</span>
        </div>
        <div className="stat-card">
          <span className="stat-value">
            {stats?.total_scanned.toLocaleString() ?? "—"}
            <span style={{ fontSize: "14px", color: "var(--text-3)", fontWeight: 400 }}>
              {" "}({scanCoverage}%)
            </span>
          </span>
          <span className="stat-label">Scanned</span>
        </div>
        <div className="stat-card">
          <span className="stat-value" style={{ color: avgColor }}>
            {stats?.average_score ?? "—"}
            <span style={{ fontSize: "16px", color: "var(--text-3)", fontWeight: 400 }}>
              /100
            </span>
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
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: "var(--s5)",
          marginBottom: "var(--s5)",
        }}
      >
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
            <p className="text-muted" style={{ fontSize: "14px" }}>
              No distribution data yet — run a scan first.
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
            <p className="text-muted" style={{ fontSize: "14px" }}>
              No finding data yet.
            </p>
          )}
        </div>
      </div>

      {/* ── Category breakdown ──────────────────────── */}
      <div className="card section-gap">
        <h2 className="section-title">Category Breakdown</h2>
        {stats?.category_breakdown && Object.keys(stats.category_breakdown).length > 0 ? (
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fill, minmax(240px, 1fr))",
              gap: "var(--s2)",
            }}
          >
            {Object.entries(stats.category_breakdown)
              .sort((a, b) => b[1] - a[1])
              .map(([cat, count]) => {
                const pct = Math.round((count / maxCatCount) * 100);
                return (
                  <a
                    key={cat}
                    href={`/?category=${cat}`}
                    style={{ textDecoration: "none" }}
                  >
                    <div
                      className="card-sm card-hover"
                      style={{ display: "flex", flexDirection: "column", gap: "var(--s2)" }}
                    >
                      <div
                        style={{
                          display: "flex",
                          justifyContent: "space-between",
                          alignItems: "center",
                        }}
                      >
                        <span
                          style={{
                            fontSize: "13px",
                            fontWeight: 600,
                            color: "var(--text)",
                          }}
                        >
                          {cat}
                        </span>
                        <span
                          style={{
                            fontSize: "12px",
                            color: "var(--text-3)",
                          }}
                        >
                          {count.toLocaleString()}
                        </span>
                      </div>
                      <div className="dist-bar-bg" style={{ height: "4px" }}>
                        <div
                          className="dist-bar-fill"
                          style={{
                            width: `${pct}%`,
                            background: "var(--accent)",
                            opacity: 0.6,
                          }}
                        />
                      </div>
                    </div>
                  </a>
                );
              })}
          </div>
        ) : (
          <p className="text-muted" style={{ fontSize: "14px" }}>
            No category data yet.
          </p>
        )}
      </div>

      {/* ── At-risk + Top-scored ────────────────────── */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: "var(--s5)",
          marginBottom: "var(--s5)",
        }}
      >
        {/* At-risk servers */}
        <div className="card">
          <h2 className="section-title">
            Highest Risk
            <span className="count">{atRisk.length}</span>
          </h2>
          {atRisk.length === 0 ? (
            <p className="text-muted" style={{ fontSize: "14px" }}>
              No critical-risk servers found.
            </p>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: "var(--s1)" }}>
              {atRisk.map((server) => (
                <div
                  key={server.id}
                  className="server-row-hover"
                >
                  <div>
                    <a
                      href={`/server/${server.slug}`}
                      style={{
                        fontSize: "13px",
                        fontWeight: 600,
                        color: "var(--text)",
                        textDecoration: "none",
                        display: "block",
                      }}
                    >
                      {server.name}
                    </a>
                    {server.category && (
                      <span
                        style={{ fontSize: "11px", color: "var(--text-3)" }}
                      >
                        {server.category}
                      </span>
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
            <p className="text-muted" style={{ fontSize: "14px" }}>
              No servers with high scores yet.
            </p>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: "var(--s1)" }}>
              {topServers.map((server) => (
                <div
                  key={server.id}
                  className="server-row-hover"
                >
                  <div>
                    <a
                      href={`/server/${server.slug}`}
                      style={{
                        fontSize: "13px",
                        fontWeight: 600,
                        color: "var(--text)",
                        textDecoration: "none",
                        display: "block",
                      }}
                    >
                      {server.name}
                    </a>
                    {server.category && (
                      <span
                        style={{ fontSize: "11px", color: "var(--text-3)" }}
                      >
                        {server.category}
                      </span>
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
          <div style={{ display: "flex", alignItems: "center", gap: "var(--s3)", marginTop: "var(--s2)" }}>
            <div className="dist-bar-bg" style={{ flex: 1, height: "8px" }}>
              <div
                className="dist-bar-fill"
                style={{
                  width: `${scanCoverage}%`,
                  background: scanCoverage >= 80 ? "var(--good)" : scanCoverage >= 50 ? "var(--moderate)" : "var(--poor)",
                  borderRadius: "4px",
                }}
              />
            </div>
            <span style={{ fontSize: "13px", color: "var(--text-2)", flexShrink: 0 }}>
              {stats.total_scanned.toLocaleString()} / {stats.total_servers.toLocaleString()} scanned ({scanCoverage}%)
            </span>
          </div>
          {stats.total_servers - stats.total_scanned > 0 && (
            <p style={{ fontSize: "12px", color: "var(--text-3)", marginTop: "var(--s2)" }}>
              {(stats.total_servers - stats.total_scanned).toLocaleString()} servers awaiting scan
            </p>
          )}
        </div>
      )}

      {/* ── Detection rule categories ─────────────────── */}
      <div className="card section-gap">
        <h2 className="section-title" style={{ marginBottom: "var(--s4)" }}>
          Detection Rules
          <span className="count">76</span>
        </h2>
        <p style={{ fontSize: "13px", color: "var(--text-3)", marginBottom: "var(--s4)" }}>
          76 rules across 9 categories — every server is evaluated against all applicable rules.
        </p>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))",
            gap: "var(--s2)",
          }}
        >
          {RULE_CATEGORIES.map((cat) => (
            <div
              key={cat.code}
              className="card-sm"
              style={{ display: "flex", alignItems: "center", gap: "var(--s3)" }}
            >
              <span
                style={{
                  fontSize: "12px",
                  fontWeight: 700,
                  color: "var(--accent)",
                  fontFamily: "var(--font-mono, monospace)",
                  flexShrink: 0,
                  width: "18px",
                }}
              >
                {cat.code}
              </span>
              <span style={{ fontSize: "12px", color: "var(--text-2)", flex: 1 }}>
                {cat.name}
              </span>
              <span style={{ fontSize: "12px", color: "var(--text-3)", fontWeight: 600 }}>
                {cat.count}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* ── OWASP MCP Top 10 overview ───────────────── */}
      <div className="card section-gap">
        <h2 className="section-title" style={{ marginBottom: "var(--s4)" }}>
          OWASP MCP Top 10 Coverage
        </h2>
        <p
          style={{
            fontSize: "13px",
            color: "var(--text-3)",
            marginBottom: "var(--s5)",
          }}
        >
          Detection rules mapped to all 10 OWASP MCP categories. Every server
          is evaluated against each category on every scan.
        </p>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))",
            gap: "var(--s2)",
          }}
        >
          {OWASP_LIST.map((owasp) => (
            <div
              key={owasp.id}
              className="card-sm"
              style={{ display: "flex", alignItems: "center", gap: "var(--s2)" }}
            >
              <span
                style={{
                  fontSize: "11px",
                  fontWeight: 700,
                  color: "var(--accent)",
                  fontFamily: "var(--font-mono, monospace)",
                  flexShrink: 0,
                }}
              >
                {owasp.id}
              </span>
              <span style={{ fontSize: "12px", color: "var(--text-2)" }}>
                {owasp.name}
              </span>
            </div>
          ))}
        </div>
      </div>
    </>
  );
}
