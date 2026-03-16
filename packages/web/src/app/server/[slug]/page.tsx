import type { Metadata } from "next";

export const dynamic = "force-dynamic";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3100";
const SITE_URL = process.env.NEXT_PUBLIC_SITE_URL || "https://mcp-sentinel.com";

// ── Types ─────────────────────────────────────────────────────────────────────

interface Tool {
  name: string;
  description: string | null;
  capability_tags: string[];
}

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

interface ScoreHistoryEntry {
  id: string;
  score: number;
  findings_count: number;
  rules_version: string | null;
  recorded_at: string;
}

interface RiskEdge {
  id: string;
  from_server_id: string;
  from_server_name: string;
  from_server_slug: string;
  to_server_id: string;
  to_server_name: string;
  to_server_slug: string;
  edge_type: string;
  pattern_id: string;
  severity: string;
  description: string;
  owasp_category: string | null;
  mitre_technique: string | null;
  detected_at: string;
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
  score_detail?: ScoreDetail;
}

// ── Data ──────────────────────────────────────────────────────────────────────

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

async function getScoreHistory(slug: string): Promise<ScoreHistoryEntry[]> {
  try {
    const res = await fetch(`${API_URL}/api/v1/servers/${encodeURIComponent(slug)}/history`, {
      signal: AbortSignal.timeout(4000),
    });
    if (!res.ok) return [];
    const data = await res.json();
    return data.data ?? [];
  } catch {
    return [];
  }
}

async function getRiskEdges(slug: string): Promise<RiskEdge[]> {
  try {
    const res = await fetch(`${API_URL}/api/v1/servers/${encodeURIComponent(slug)}/risk-edges`, {
      signal: AbortSignal.timeout(4000),
    });
    if (!res.ok) return [];
    const data = await res.json();
    return data.data ?? [];
  } catch {
    return [];
  }
}

// ── Metadata ──────────────────────────────────────────────────────────────────

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

/** SVG score ring — pure server-rendered, no JS */
function ScoreRing({ score }: { score: number | null }) {
  const r = 36;
  const circ = 2 * Math.PI * r;
  const pct = score !== null ? score / 100 : 0;
  const offset = circ * (1 - pct);
  const color = scoreColor(score);

  return (
    <div style={{ position: "relative", width: 100, height: 100 }}>
      <svg
        width="100"
        height="100"
        viewBox="0 0 100 100"
        style={{ transform: "rotate(-90deg)" }}
        aria-hidden="true"
      >
        {/* Track */}
        <circle
          cx="50"
          cy="50"
          r={r}
          fill="none"
          stroke="var(--surface-3)"
          strokeWidth="8"
        />
        {/* Fill */}
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
            style={{ transition: "stroke-dashoffset 0.6s cubic-bezier(0.16,1,0.3,1)" }}
          />
        )}
      </svg>
      <div
        style={{
          position: "absolute",
          inset: 0,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
        }}
      >
        <span
          style={{
            fontSize: score !== null ? "22px" : "13px",
            fontWeight: 800,
            letterSpacing: "-0.04em",
            color,
            lineHeight: 1,
          }}
        >
          {score !== null ? score : "—"}
        </span>
        {score !== null && (
          <span style={{ fontSize: "9px", color: "var(--text-3)", fontWeight: 600, letterSpacing: "0.04em" }}>
            / 100
          </span>
        )}
      </div>
    </div>
  );
}

function SubScoreBar({
  label,
  value,
}: {
  label: string;
  value: number | undefined;
}) {
  const v = value ?? 100;
  const color =
    v >= 80 ? "var(--good)" : v >= 60 ? "var(--moderate)" : v >= 40 ? "var(--poor)" : "var(--critical)";
  return (
    <div className="subscore-row">
      <span className="subscore-label">{label}</span>
      <div className="subscore-bar-bg">
        <div
          className="subscore-bar-fill"
          style={{ width: `${v}%`, background: color }}
        />
      </div>
      <span className="subscore-val">{v}</span>
    </div>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={`sev-badge sev-${severity}`}>{severity}</span>
  );
}

function CapTag({ tag }: { tag: string }) {
  const cls = `cap-tag cap-${tag}`;
  const labels: Record<string, string> = {
    "reads-data": "reads data",
    "writes-data": "writes data",
    "executes-code": "executes code",
    "sends-network": "network",
    "accesses-filesystem": "filesystem",
    "manages-credentials": "credentials",
  };
  return <span className={cls}>{labels[tag] ?? tag}</span>;
}

function fmtNum(n: number | null): string {
  if (n == null) return "—";
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return n.toLocaleString();
}

function fmtDate(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" });
}

function ConnectionStatusBadge({ status }: { status: string | null }) {
  if (!status) return null;
  const colors: Record<string, string> = {
    success: "var(--good)",
    failed: "var(--critical)",
    timeout: "var(--poor)",
    no_endpoint: "var(--text-3)",
  };
  const labels: Record<string, string> = {
    success: "Connected",
    failed: "Connection Failed",
    timeout: "Timed Out",
    no_endpoint: "No Endpoint",
  };
  return (
    <span
      style={{
        fontSize: "11px",
        fontWeight: 600,
        color: colors[status] || "var(--text-3)",
        display: "inline-flex",
        alignItems: "center",
        gap: "4px",
      }}
    >
      <span
        style={{
          width: 6,
          height: 6,
          borderRadius: "50%",
          background: colors[status] || "var(--text-3)",
          display: "inline-block",
        }}
      />
      {labels[status] || status}
    </span>
  );
}

/** CSS-only score history sparkline — shows trend over last 10 scans */
function ScoreHistoryTimeline({ history }: { history: ScoreHistoryEntry[] }) {
  if (history.length < 2) return null;

  // Show last 10 entries, oldest first
  const entries = history.slice(0, 10).reverse();
  const maxScore = 100;

  return (
    <div className="card">
      <h3
        style={{
          fontSize: "12px",
          fontWeight: 700,
          textTransform: "uppercase",
          letterSpacing: "0.06em",
          color: "var(--text-3)",
          marginBottom: "var(--s3)",
        }}
      >
        Score History
      </h3>
      <div
        style={{
          display: "flex",
          alignItems: "flex-end",
          gap: "3px",
          height: "60px",
        }}
      >
        {entries.map((entry, i) => {
          const height = Math.max(4, (entry.score / maxScore) * 60);
          const color =
            entry.score >= 80
              ? "var(--good)"
              : entry.score >= 60
                ? "var(--moderate)"
                : entry.score >= 40
                  ? "var(--poor)"
                  : "var(--critical)";
          const date = new Date(entry.recorded_at).toLocaleDateString("en-US", {
            month: "short",
            day: "numeric",
          });
          return (
            <div
              key={entry.id}
              title={`${date}: ${entry.score}/100 (${entry.findings_count} findings)`}
              style={{
                flex: 1,
                height: `${height}px`,
                background: color,
                borderRadius: "2px 2px 0 0",
                opacity: i === entries.length - 1 ? 1 : 0.6,
                transition: "opacity 0.2s",
                cursor: "default",
                minWidth: "6px",
              }}
            />
          );
        })}
      </div>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          fontSize: "10px",
          color: "var(--text-3)",
          marginTop: "4px",
        }}
      >
        <span>
          {new Date(entries[0].recorded_at).toLocaleDateString("en-US", {
            month: "short",
            day: "numeric",
          })}
        </span>
        <span>
          {new Date(entries[entries.length - 1].recorded_at).toLocaleDateString(
            "en-US",
            { month: "short", day: "numeric" }
          )}
        </span>
      </div>
    </div>
  );
}

const SEV_ORDER: Finding["severity"][] = [
  "critical",
  "high",
  "medium",
  "low",
  "informational",
];

// ── Check coverage & framework compliance data ────────────────────────────────

const RULE_CATEGORIES: { prefix: string; name: string; count: number }[] = [
  { prefix: "A", name: "Description Analysis", count: 9 },
  { prefix: "B", name: "Schema Analysis", count: 7 },
  { prefix: "C", name: "Code Analysis", count: 16 },
  { prefix: "D", name: "Dependency Analysis", count: 7 },
  { prefix: "E", name: "Behavioral Analysis", count: 4 },
  { prefix: "F", name: "Ecosystem Context", count: 7 },
  { prefix: "G", name: "Adversarial AI", count: 7 },
  { prefix: "H", name: "2026 Attack Surface", count: 3 },
  { prefix: "I", name: "Protocol Surface", count: 16 },
  { prefix: "J", name: "Threat Intelligence", count: 7 },
  { prefix: "K", name: "Compliance & Governance", count: 20 },
];

const FRAMEWORKS: {
  id: string;
  name: string;
  ruleIds: string[];
  checkMitreTechnique?: boolean;
}[] = [
  {
    id: "nist-ai-rmf",
    name: "NIST AI RMF",
    ruleIds: ["K1", "K3", "K4", "K18"],
  },
  {
    id: "owasp-agentic",
    name: "OWASP Agentic Top 10",
    ruleIds: ["K5", "K6", "K7", "K8", "K9", "K10", "K12", "K13", "K14", "K15", "K16", "K17"],
  },
  {
    id: "mitre-atlas",
    name: "MITRE ATLAS",
    ruleIds: ["K9", "K14"],
    checkMitreTechnique: true,
  },
  {
    id: "eu-ai-act",
    name: "EU AI Act",
    ruleIds: ["K2", "K4", "K5", "K16", "K17"],
  },
  {
    id: "iso-42001",
    name: "ISO 42001",
    ruleIds: ["K4", "K5", "K20"],
  },
  {
    id: "iso-27001",
    name: "ISO 27001",
    ruleIds: ["K1", "K2", "K3", "K6", "K7", "K8", "K10", "K11", "K18", "K19", "K20"],
  },
  {
    id: "cosai",
    name: "CoSAI MCP Security",
    ruleIds: ["K1", "K2", "K3", "K6", "K7", "K8", "K9", "K10", "K11", "K12", "K13", "K15", "K16", "K17", "K18", "K19"],
  },
  {
    id: "maestro",
    name: "MAESTRO",
    ruleIds: ["K1", "K3", "K8", "K11", "K13", "K14", "K15", "K17", "K19", "K20"],
  },
];

const OWASP_LABELS: Record<string, string> = {
  "MCP01-prompt-injection": "MCP01 Prompt Injection",
  "MCP02-tool-poisoning": "MCP02 Tool Poisoning",
  "MCP03-command-injection": "MCP03 Command Injection",
  "MCP04-data-exfiltration": "MCP04 Data Exfiltration",
  "MCP05-privilege-escalation": "MCP05 Privilege Escalation",
  "MCP06-excessive-permissions": "MCP06 Excessive Permissions",
  "MCP07-insecure-configuration": "MCP07 Insecure Config",
  "MCP08-dependency-vulnerabilities": "MCP08 Dependencies",
  "MCP09-logging-monitoring": "MCP09 Logging",
  "MCP10-supply-chain": "MCP10 Supply Chain",
};

// ── JSON-LD ───────────────────────────────────────────────────────────────────

function buildJsonLd(server: ServerDetail, siteUrl: string) {
  const jsonLd: Record<string, unknown> = {
    "@context": "https://schema.org",
    "@type": "SoftwareApplication",
    name: server.name,
    applicationCategory: "SecurityApplication",
    url: `${siteUrl}/server/${server.slug}`,
    ...(server.description && { description: server.description }),
    ...(server.github_url && { codeRepository: server.github_url }),
    ...(server.npm_package && {
      downloadUrl: `https://www.npmjs.com/package/${server.npm_package}`,
    }),
  };

  if (server.latest_score !== null) {
    jsonLd["aggregateRating"] = {
      "@type": "AggregateRating",
      ratingValue: server.latest_score,
      bestRating: 100,
      worstRating: 0,
      ratingCount: 1,
      reviewAspect: "Security",
    };
  }

  if (server.author) {
    jsonLd["author"] = { "@type": "Person", name: server.author };
  }

  return jsonLd;
}

// ── Security Check Coverage ───────────────────────────────────────────────────

function SecurityCheckCoverage({
  findings,
  score,
}: {
  findings: Finding[];
  score: number | null;
}) {
  if (score === null) return null;

  // Index findings by category prefix
  const byPrefix = new Map<string, Finding[]>();
  for (const f of findings) {
    const p = f.rule_id.charAt(0).toUpperCase();
    if (!byPrefix.has(p)) byPrefix.set(p, []);
    byPrefix.get(p)!.push(f);
  }

  const failCount = RULE_CATEGORIES.filter(
    (c) => (byPrefix.get(c.prefix) ?? []).length > 0
  ).length;

  return (
    <section className="section-gap">
      <h2 className="section-title">
        Security Check Coverage
        <span className="count">103 checks</span>
      </h2>
      <div
        style={{
          fontSize: "12px",
          color: "var(--text-3)",
          marginBottom: "var(--s3)",
        }}
      >
        11 categories ·{" "}
        <span style={{ color: "var(--good)", fontWeight: 600 }}>
          {11 - failCount} passed
        </span>
        {failCount > 0 && (
          <>
            {" · "}
            <span style={{ color: "var(--critical)", fontWeight: 600 }}>
              {failCount} flagged
            </span>
          </>
        )}
      </div>
      <div className="checks-grid">
        {RULE_CATEGORIES.map((cat) => {
          const catFindings = byPrefix.get(cat.prefix) ?? [];
          const passed = catFindings.length === 0;
          const worstSev = passed
            ? null
            : SEV_ORDER.find((s) => catFindings.some((f) => f.severity === s)) ?? null;
          const statusColor =
            worstSev === "critical"
              ? "var(--critical)"
              : worstSev === "high"
                ? "var(--poor)"
                : worstSev === "medium"
                  ? "var(--moderate)"
                  : worstSev
                    ? "var(--text-2)"
                    : "var(--good)";
          return (
            <div key={cat.prefix} className="check-row">
              <span className="check-prefix">{cat.prefix}</span>
              <span className="check-name">{cat.name}</span>
              <span className="check-rule-count">{cat.count} rules</span>
              <span className="check-status" style={{ color: statusColor }}>
                {passed
                  ? "✓ Passed"
                  : `${catFindings.length} issue${catFindings.length !== 1 ? "s" : ""}`}
              </span>
            </div>
          );
        })}
      </div>
    </section>
  );
}

// ── Framework Compliance Card ─────────────────────────────────────────────────

function FrameworkComplianceCard({ findings }: { findings: Finding[] }) {
  if (findings === undefined) return null;

  const findingRuleIds = new Set(findings.map((f) => f.rule_id));
  const hasMitreTechnique = findings.some((f) => f.mitre_technique);

  return (
    <div className="card">
      <h3
        style={{
          fontSize: "12px",
          fontWeight: 700,
          textTransform: "uppercase",
          letterSpacing: "0.06em",
          color: "var(--text-3)",
          marginBottom: "var(--s3)",
        }}
      >
        Framework Compliance
      </h3>
      <div style={{ display: "flex", flexDirection: "column" }}>
        {FRAMEWORKS.map((fw) => {
          const violatedRules = fw.ruleIds.filter((r) => findingRuleIds.has(r));
          const failed =
            violatedRules.length > 0 ||
            (fw.checkMitreTechnique && hasMitreTechnique);
          return (
            <div key={fw.id} className={`framework-row ${failed ? "fw-fail" : "fw-pass"}`}>
              <span className="fw-dot" />
              <span className="fw-name">{fw.name}</span>
              <span className="fw-status">
                {failed
                  ? `${violatedRules.length + (fw.checkMitreTechnique && hasMitreTechnique && !violatedRules.length ? 1 : 0)} issue${violatedRules.length !== 1 ? "s" : ""}`
                  : "Clean"}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default async function ServerPage({
  params,
}: {
  params: Promise<{ slug: string }>;
}) {
  const { slug } = await params;
  const [server, scoreHistory, riskEdges] = await Promise.all([
    getServer(slug),
    getScoreHistory(slug),
    getRiskEdges(slug),
  ]);

  if (!server) {
    return (
      <div className="notfound" style={{ minHeight: "60vh" }}>
        <div className="notfound-code">404</div>
        <h1 className="notfound-title">Server not found</h1>
        <p className="notfound-sub">
          We don&apos;t have a record for &ldquo;{slug}&rdquo;.
        </p>
        <a href="/" className="btn-primary">
          ← Back to registry
        </a>
      </div>
    );
  }

  const score = server.latest_score;
  const sd = server.score_detail;

  // Group findings by severity
  const findingsBySev = SEV_ORDER.reduce<Record<string, Finding[]>>(
    (acc, sev) => {
      const matches = (server.findings || []).filter((f) => f.severity === sev);
      if (matches.length) acc[sev] = matches;
      return acc;
    },
    {}
  );

  const totalFindings = server.findings?.length ?? 0;
  const criticalCount = (server.findings || []).filter(
    (f) => f.severity === "critical"
  ).length;

  const badgeMd = `[![MCP Sentinel Score](${API_URL}/api/v1/servers/${server.slug}/badge.svg)](${SITE_URL}/server/${server.slug})`;

  const jsonLd = buildJsonLd(server, SITE_URL);

  return (
    <>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
      />
      {/* ── Breadcrumb + Header ──────────────────────── */}
      <div className="server-header">
        <nav className="breadcrumb" aria-label="Breadcrumb">
          <a href="/">Registry</a>
          <span>›</span>
          {server.category && (
            <>
              <a href={`/?category=${server.category}`}>{server.category}</a>
              <span>›</span>
            </>
          )}
          <span style={{ color: "var(--text-2)" }}>{server.name}</span>
        </nav>

        <h1 className="server-title">{server.name}</h1>

        {server.description && (
          <p
            style={{
              color: "var(--text-2)",
              fontSize: "15px",
              lineHeight: "1.6",
              maxWidth: "640px",
              marginBottom: "var(--s4)",
            }}
          >
            {server.description}
          </p>
        )}

        <div className="server-meta">
          {server.author && <span>by {server.author}</span>}
          {server.language && (
            <span className="category-chip">{server.language}</span>
          )}
          {server.license && (
            <span style={{ color: "var(--text-3)", fontSize: "13px" }}>
              {server.license}
            </span>
          )}
          {server.last_commit && (
            <span style={{ color: "var(--text-3)", fontSize: "13px" }}>
              Last commit {fmtDate(server.last_commit)}
            </span>
          )}
          <ConnectionStatusBadge status={server.connection_status} />
        </div>

        <div className="server-links">
          {server.github_url && (
            <a
              href={server.github_url}
              className="ext-link"
              target="_blank"
              rel="noopener noreferrer"
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 2C6.477 2 2 6.477 2 12c0 4.418 2.865 8.166 6.839 9.489.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.604-3.369-1.34-3.369-1.34-.454-1.155-1.11-1.463-1.11-1.463-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.029-2.683-.103-.253-.446-1.27.098-2.647 0 0 .84-.269 2.75 1.025A9.578 9.578 0 0112 6.836a9.59 9.59 0 012.504.337c1.909-1.294 2.747-1.025 2.747-1.025.546 1.377.202 2.394.1 2.647.64.699 1.028 1.592 1.028 2.683 0 3.842-2.339 4.687-4.566 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.743 0 .269.18.579.688.481C19.138 20.163 22 16.418 22 12c0-5.523-4.477-10-10-10z" />
              </svg>
              GitHub
            </a>
          )}
          {server.npm_package && (
            <a
              href={`https://www.npmjs.com/package/${server.npm_package}`}
              className="ext-link"
              target="_blank"
              rel="noopener noreferrer"
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
                <path d="M0 7.334v8h6.666v1.332H12v-1.332h12v-8H0zm6.666 6.664H5.334v-4H3.999v4H1.335V8.667h5.331v5.331zm4 0v1.336H8.001V8.667h5.334v5.332h-2.669v-.001zm12.001 0h-1.33v-4h-1.336v4h-1.335v-4h-1.33v4h-2.671V8.667h8.002v5.331z" />
              </svg>
              npm
            </a>
          )}
          {server.pypi_package && (
            <a
              href={`https://pypi.org/project/${server.pypi_package}`}
              className="ext-link"
              target="_blank"
              rel="noopener noreferrer"
            >
              PyPI
            </a>
          )}
        </div>
      </div>

      {/* ── Quick stats ──────────────────────────────── */}
      <div className="mini-stats">
        <div className="mini-stat">
          <div className="mini-stat-val">{server.tools?.length ?? 0}</div>
          <div className="mini-stat-label">Tools</div>
        </div>
        <div className="mini-stat">
          <div
            className="mini-stat-val"
            style={{ color: criticalCount > 0 ? "var(--critical)" : "var(--text)" }}
          >
            {totalFindings}
          </div>
          <div className="mini-stat-label">Findings</div>
        </div>
        <div className="mini-stat">
          <div className="mini-stat-val">{fmtNum(server.github_stars)}</div>
          <div className="mini-stat-label">Stars</div>
        </div>
        <div className="mini-stat">
          <div className="mini-stat-val">{fmtNum(server.npm_downloads)}</div>
          <div className="mini-stat-label">Downloads</div>
        </div>
      </div>

      {/* ── Two-column layout ────────────────────────── */}
      <div className="detail-layout">
        {/* ── Main column ──────────────────────────────── */}
        <div className="detail-main">

          {/* Not yet scanned banner */}
          {score === null && totalFindings === 0 && (!server.tools || server.tools.length === 0) && (
            <div
              className="card"
              style={{
                textAlign: "center",
                padding: "var(--s10)",
                marginBottom: "var(--s5)",
                color: "var(--text-3)",
              }}
            >
              <div style={{ fontSize: "28px", marginBottom: "var(--s2)" }}>
                ◎
              </div>
              <div style={{ fontWeight: 600, color: "var(--text-2)", marginBottom: "var(--s1)" }}>
                Not yet scanned
              </div>
              <p style={{ fontSize: "13px", maxWidth: "400px", margin: "0 auto" }}>
                This server has been discovered but hasn&apos;t been analyzed yet.
                It will be scanned in the next pipeline run.
              </p>
            </div>
          )}

          {/* Tools */}
          {server.tools && server.tools.length > 0 ? (
            <section className="section-gap">
              <h2 className="section-title">
                Tools{" "}
                <span className="count">{server.tools.length}</span>
              </h2>
              <div className="tools-grid">
                {server.tools.map((tool) => (
                  <div key={tool.name} className="tool-card">
                    <div className="tool-name">{tool.name}</div>
                    {tool.description && (
                      <p className="tool-desc">{tool.description}</p>
                    )}
                    {tool.capability_tags?.length > 0 && (
                      <div className="tool-caps">
                        {tool.capability_tags.map((tag) => (
                          <CapTag key={tag} tag={tag} />
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </section>
          ) : score !== null ? (
            <section className="section-gap">
              <h2 className="section-title">Tools</h2>
              <p style={{ fontSize: "13px", color: "var(--text-3)" }}>
                No tools enumerated — the server may not expose tools via <code>tools/list</code>,
                or the connection could not be established.
              </p>
            </section>
          ) : null}

          {/* Findings */}
          <section className="section-gap">
            <h2 className="section-title">
              Security Findings{" "}
              <span className="count">{totalFindings}</span>
              {criticalCount > 0 && (
                <span
                  className="sev-badge sev-critical"
                  style={{ marginLeft: "var(--s2)" }}
                >
                  {criticalCount} critical
                </span>
              )}
            </h2>

            {totalFindings === 0 ? (
              <div
                className="card"
                style={{
                  textAlign: "center",
                  padding: "var(--s10)",
                  color: "var(--good)",
                }}
              >
                <div style={{ fontSize: "32px", marginBottom: "var(--s2)" }}>
                  ✓
                </div>
                <div style={{ fontWeight: 600, marginBottom: "var(--s1)" }}>
                  No findings detected
                </div>
                <div style={{ fontSize: "13px", color: "var(--text-3)" }}>
                  This server passed all 103 detection rules.
                </div>
              </div>
            ) : (
              <div className="findings-list">
                {SEV_ORDER.map(
                  (sev) =>
                    findingsBySev[sev] && (
                      <div key={sev}>
                        <div
                          style={{
                            display: "flex",
                            alignItems: "center",
                            gap: "var(--s2)",
                            marginBottom: "var(--s2)",
                            marginTop: "var(--s4)",
                          }}
                        >
                          <SeverityBadge severity={sev} />
                          <span
                            style={{
                              fontSize: "12px",
                              color: "var(--text-3)",
                            }}
                          >
                            {findingsBySev[sev].length} finding
                            {findingsBySev[sev].length !== 1 ? "s" : ""}
                          </span>
                        </div>
                        {findingsBySev[sev].map((finding) => (
                          <div
                            key={finding.id}
                            className={`finding-card finding-${finding.severity}`}
                            style={{ marginBottom: "var(--s2)" }}
                          >
                            <div className="finding-header">
                              <SeverityBadge severity={finding.severity} />
                              <span className="finding-rule-id">
                                {finding.rule_id}
                              </span>
                              {finding.mitre_technique && (
                                <span
                                  style={{
                                    fontSize: "11px",
                                    color: "var(--text-3)",
                                    fontFamily: "var(--font-mono, monospace)",
                                  }}
                                >
                                  {finding.mitre_technique}
                                </span>
                              )}
                              {finding.owasp_category && (
                                <span className="finding-owasp">
                                  {finding.owasp_category}
                                </span>
                              )}
                            </div>
                            <p className="finding-evidence">
                              {finding.evidence}
                            </p>
                            <p className="finding-remediation">
                              {finding.remediation}
                            </p>
                          </div>
                        ))}
                      </div>
                    )
                )}
              </div>
            )}
          </section>

          {/* Security Check Coverage */}
          {score !== null && (
            <SecurityCheckCoverage
              findings={server.findings ?? []}
              score={score}
            />
          )}

          {/* Badge embed */}
          <section>
            <h2 className="section-title">Add to your README</h2>
            <div className="card" style={{ gap: "var(--s3)", display: "flex", flexDirection: "column" }}>
              <p style={{ fontSize: "13px", color: "var(--text-3)" }}>
                Show your security score in your repository&apos;s README.
              </p>
              <pre className="badge-embed">{badgeMd}</pre>
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "var(--s3)",
                }}
              >
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img
                  src={`${API_URL}/api/v1/servers/${server.slug}/badge.svg`}
                  alt={`MCP Sentinel score for ${server.name}`}
                />
                <span style={{ fontSize: "12px", color: "var(--text-3)" }}>
                  Updates automatically on each scan.
                </span>
              </div>
            </div>
          </section>
        </div>

        {/* ── Sidebar ──────────────────────────────────── */}
        <aside className="detail-sidebar">
          {/* Score ring */}
          <div className="score-ring-card">
            <p className="score-ring-label">Security Score</p>
            <ScoreRing score={score} />
            <p
              style={{
                fontSize: "13px",
                fontWeight: 600,
                color: scoreColor(score),
              }}
            >
              {scoreLabel(score)}
            </p>

            {/* Sub-scores */}
            {sd && (
              <div className="subscores">
                <SubScoreBar label="Code" value={sd.code_score} />
                <SubScoreBar label="Dependencies" value={sd.deps_score} />
                <SubScoreBar label="Config" value={sd.config_score} />
                <SubScoreBar label="Description" value={sd.description_score} />
                <SubScoreBar label="Behavior" value={sd.behavior_score} />
              </div>
            )}
          </div>

          {/* OWASP coverage */}
          {sd?.owasp_coverage &&
            Object.keys(sd.owasp_coverage).length > 0 && (
              <div className="card">
                <h3
                  style={{
                    fontSize: "12px",
                    fontWeight: 700,
                    textTransform: "uppercase",
                    letterSpacing: "0.06em",
                    color: "var(--text-3)",
                    marginBottom: "var(--s3)",
                  }}
                >
                  OWASP MCP Coverage
                </h3>
                <div className="owasp-grid">
                  {Object.entries(sd.owasp_coverage).map(([key, clean]) => (
                    <div
                      key={key}
                      className={`owasp-item ${clean ? "clean" : "dirty"}`}
                      title={OWASP_LABELS[key] ?? key}
                    >
                      <span className="owasp-dot" />
                      <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {key.split("-")[0]}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

          {/* Framework Compliance */}
          {score !== null && (
            <FrameworkComplianceCard findings={server.findings ?? []} />
          )}

          {/* Cross-server attack paths */}
          {riskEdges.length > 0 && (
            <div className="card">
              <h3
                style={{
                  fontSize: "12px",
                  fontWeight: 700,
                  textTransform: "uppercase",
                  letterSpacing: "0.06em",
                  color: "var(--text-3)",
                  marginBottom: "var(--s3)",
                }}
              >
                Cross-Server Attack Paths
              </h3>
              <div style={{ display: "flex", flexDirection: "column", gap: "var(--s3)" }}>
                {riskEdges.slice(0, 5).map((edge) => {
                  const isSource = edge.from_server_slug === slug;
                  const peerName = isSource ? edge.to_server_name : edge.from_server_name;
                  const peerSlug = isSource ? edge.to_server_slug : edge.from_server_slug;
                  const sevColor = edge.severity === "critical"
                    ? "var(--critical)"
                    : edge.severity === "high"
                      ? "var(--poor)"
                      : edge.severity === "medium"
                        ? "var(--moderate)"
                        : "var(--text-3)";
                  return (
                    <div
                      key={edge.id}
                      style={{
                        padding: "var(--s2) var(--s3)",
                        background: "var(--surface-2)",
                        borderRadius: "var(--r-sm)",
                        borderLeft: `3px solid ${sevColor}`,
                      }}
                    >
                      <div style={{ display: "flex", alignItems: "center", gap: "var(--s2)", marginBottom: "4px" }}>
                        <span
                          style={{
                            fontSize: "10px",
                            fontWeight: 700,
                            textTransform: "uppercase",
                            color: sevColor,
                            letterSpacing: "0.04em",
                          }}
                        >
                          {edge.severity}
                        </span>
                        <span style={{ fontSize: "10px", color: "var(--text-3)", fontFamily: "'JetBrains Mono', monospace" }}>
                          {edge.pattern_id}
                        </span>
                      </div>
                      <p style={{ fontSize: "11px", color: "var(--text-2)", margin: "0 0 4px" }}>
                        {edge.edge_type.replace(/_/g, " ")}
                        {" — "}
                        <a
                          href={`/server/${peerSlug}`}
                          style={{ color: "var(--accent)" }}
                        >
                          {peerName}
                        </a>
                      </p>
                      <p style={{ fontSize: "11px", color: "var(--text-3)", margin: 0, lineHeight: 1.4 }}>
                        {edge.description.length > 100
                          ? edge.description.slice(0, 100) + "…"
                          : edge.description}
                      </p>
                    </div>
                  );
                })}
                {riskEdges.length > 5 && (
                  <p style={{ fontSize: "11px", color: "var(--text-3)", textAlign: "center" }}>
                    +{riskEdges.length - 5} more attack paths
                  </p>
                )}
              </div>
            </div>
          )}

          {/* Score history timeline */}
          <ScoreHistoryTimeline history={scoreHistory} />

          {/* Scan metadata */}
          {(server.last_scanned_at || server.server_version || server.endpoint_url) && (
            <div className="card">
              <h3
                style={{
                  fontSize: "12px",
                  fontWeight: 700,
                  textTransform: "uppercase",
                  letterSpacing: "0.06em",
                  color: "var(--text-3)",
                  marginBottom: "var(--s3)",
                }}
              >
                Scan Info
              </h3>
              <dl
                style={{
                  display: "grid",
                  gridTemplateColumns: "auto 1fr",
                  gap: "var(--s1) var(--s3)",
                  fontSize: "12px",
                }}
              >
                {server.last_scanned_at && (
                  <>
                    <dt style={{ color: "var(--text-3)" }}>Last scan</dt>
                    <dd style={{ color: "var(--text-2)" }}>{fmtDate(server.last_scanned_at)}</dd>
                  </>
                )}
                {server.server_version && (
                  <>
                    <dt style={{ color: "var(--text-3)" }}>Server ver.</dt>
                    <dd style={{ color: "var(--text-2)", fontFamily: "var(--font-mono, monospace)" }}>{server.server_version}</dd>
                  </>
                )}
                {server.endpoint_url && (
                  <>
                    <dt style={{ color: "var(--text-3)" }}>Endpoint</dt>
                    <dd style={{ color: "var(--text-2)", fontFamily: "var(--font-mono, monospace)", fontSize: "11px", wordBreak: "break-all" }}>{server.endpoint_url}</dd>
                  </>
                )}
              </dl>
            </div>
          )}

          {/* Metadata card */}
          <div className="card">
            <h3
              style={{
                fontSize: "12px",
                fontWeight: 700,
                textTransform: "uppercase",
                letterSpacing: "0.06em",
                color: "var(--text-3)",
                marginBottom: "var(--s3)",
              }}
            >
              Details
            </h3>
            <dl
              style={{
                display: "grid",
                gridTemplateColumns: "auto 1fr",
                gap: "var(--s1) var(--s3)",
                fontSize: "12px",
              }}
            >
              {server.category && (
                <>
                  <dt style={{ color: "var(--text-3)" }}>Category</dt>
                  <dd style={{ color: "var(--text-2)" }}>{server.category}</dd>
                </>
              )}
              {server.language && (
                <>
                  <dt style={{ color: "var(--text-3)" }}>Language</dt>
                  <dd style={{ color: "var(--text-2)" }}>{server.language}</dd>
                </>
              )}
              {server.license && (
                <>
                  <dt style={{ color: "var(--text-3)" }}>License</dt>
                  <dd style={{ color: "var(--text-2)" }}>{server.license}</dd>
                </>
              )}
              {server.github_stars !== null && (
                <>
                  <dt style={{ color: "var(--text-3)" }}>Stars</dt>
                  <dd style={{ color: "var(--text-2)" }}>
                    {fmtNum(server.github_stars)}
                  </dd>
                </>
              )}
              {server.npm_downloads !== null && (
                <>
                  <dt style={{ color: "var(--text-3)" }}>Downloads</dt>
                  <dd style={{ color: "var(--text-2)" }}>
                    {fmtNum(server.npm_downloads)}
                  </dd>
                </>
              )}
              {server.last_commit && (
                <>
                  <dt style={{ color: "var(--text-3)" }}>Last commit</dt>
                  <dd style={{ color: "var(--text-2)" }}>
                    {fmtDate(server.last_commit)}
                  </dd>
                </>
              )}
            </dl>
          </div>
        </aside>
      </div>
    </>
  );
}
