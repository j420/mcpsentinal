import type { Metadata } from "next";
import { notFound } from "next/navigation";

export const dynamic = "force-dynamic";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3100";

// ── Types ─────────────────────────────────────────────────────────────────────

interface Server {
  id: string;
  name: string;
  slug: string;
  description: string | null;
  author: string | null;
  category: string | null;
  language: string | null;
  github_stars: number | null;
  npm_downloads: number | null;
  latest_score: number | null;
  last_commit: string | null;
}

interface Pagination {
  total: number;
  page: number;
  limit: number;
  pages: number;
}

// ── Category metadata ──────────────────────────────────────────────────────────

const CATEGORIES = [
  "database",
  "filesystem",
  "api-integration",
  "dev-tools",
  "ai-ml",
  "communication",
  "cloud-infra",
  "security",
  "data-processing",
  "monitoring",
  "search",
  "browser-web",
  "code-execution",
  "other",
] as const;

type CategorySlug = (typeof CATEGORIES)[number];

const CATEGORY_META: Record<
  CategorySlug,
  { label: string; description: string; riskNote: string; icon: React.ReactNode }
> = {
  database: {
    label: "Database",
    description:
      "Connectors for SQL, NoSQL, vector, and time-series databases — query execution, schema inspection, and data management.",
    riskNote: "SQL injection · credential exposure · schema leakage",
    icon: <DatabaseIcon />,
  },
  filesystem: {
    label: "Filesystem",
    description:
      "Servers that read, write, list, or watch files on the local or remote filesystem, including cloud storage backends.",
    riskNote: "Path traversal · arbitrary write · data exfiltration",
    icon: <FilesystemIcon />,
  },
  "api-integration": {
    label: "API Integration",
    description:
      "Wrappers around third-party REST, GraphQL, and webhook APIs — Stripe, Twilio, SendGrid, GitHub, and similar services.",
    riskNote: "OAuth misconfiguration · token exposure · SSRF",
    icon: <ApiIcon />,
  },
  "dev-tools": {
    label: "Dev Tools",
    description:
      "Development tooling — code search, linters, test runners, build systems, and IDE integrations.",
    riskNote: "Command injection · arbitrary code execution",
    icon: <DevToolsIcon />,
  },
  "ai-ml": {
    label: "AI / ML",
    description:
      "Machine learning model inference, embedding generation, vector similarity search, and AI pipeline orchestration.",
    riskNote: "Prompt injection · model poisoning · data leakage",
    icon: <AiMlIcon />,
  },
  communication: {
    label: "Communication",
    description:
      "Email, Slack, Discord, and messaging platform integrations — read and send messages, manage channels.",
    riskNote: "Indirect injection via messages · phishing via send",
    icon: <CommunicationIcon />,
  },
  "cloud-infra": {
    label: "Cloud Infra",
    description:
      "AWS, GCP, Azure, and cloud-native tools — infrastructure provisioning, resource management, and deployment.",
    riskNote: "Excessive IAM permissions · privilege escalation",
    icon: <CloudInfraIcon />,
  },
  security: {
    label: "Security",
    description:
      "Security-focused tools — vulnerability scanners, secret detection, penetration testing aids, and compliance checks.",
    riskNote: "Privilege abuse · scanner blind spots · false safety",
    icon: <SecurityIcon />,
  },
  "data-processing": {
    label: "Data Processing",
    description:
      "ETL pipelines, data transformation, format conversion, CSV/JSON/XML parsing, and stream processing.",
    riskNote: "Unsafe deserialization · template injection · DoS",
    icon: <DataProcessingIcon />,
  },
  monitoring: {
    label: "Monitoring",
    description:
      "Observability tooling — metrics, logs, traces, alerts, dashboards, and on-call integrations.",
    riskNote: "Log injection · sensitive data in telemetry",
    icon: <MonitoringIcon />,
  },
  search: {
    label: "Search",
    description:
      "Full-text and semantic search across codebases, documents, databases, and the web.",
    riskNote: "Indirect injection via search results · SSRF",
    icon: <SearchIcon />,
  },
  "browser-web": {
    label: "Browser / Web",
    description:
      "Browser automation, web scraping, screenshot capture, and general HTTP request execution.",
    riskNote: "Indirect injection via web content · CSRF · SSRF",
    icon: <BrowserWebIcon />,
  },
  "code-execution": {
    label: "Code Execution",
    description:
      "REPL environments, sandbox runners, shell command execution, and scripting language interpreters.",
    riskNote: "Arbitrary execution · sandbox escape · RCE",
    icon: <CodeExecutionIcon />,
  },
  other: {
    label: "Other",
    description:
      "Miscellaneous MCP servers that don't fit a primary category — utilities, experiments, and niche integrations.",
    riskNote: "Varies — review individual server findings",
    icon: <OtherIcon />,
  },
};


export async function generateMetadata({
  params,
}: {
  params: Promise<{ category: string }>;
}): Promise<Metadata> {
  const { category } = await params;
  const meta = CATEGORY_META[category as CategorySlug];
  if (!meta) return {};
  return {
    title: `${meta.label} MCP Servers`,
    description: `Browse ${meta.label} MCP servers ranked by security score. ${meta.description}`,
    openGraph: {
      title: `${meta.label} MCP Servers — MCP Sentinel`,
      description: `Browse ${meta.label} MCP servers ranked by security score. ${meta.description}`,
    },
  };
}

// ── Data fetching ──────────────────────────────────────────────────────────────

async function getCategoryServers(params: {
  category: string;
  sort?: string;
  order?: string;
  page?: number;
  min_score?: string;
}): Promise<{ servers: Server[]; pagination: Pagination }> {
  try {
    const sp = new URLSearchParams();
    sp.set("category", params.category);
    sp.set("limit", "25");
    sp.set("sort", params.sort || "score");
    sp.set("order", params.order || "desc");
    if (params.page && params.page > 1) sp.set("page", String(params.page));
    if (params.min_score) sp.set("min_score", params.min_score);

    const res = await fetch(`${API_URL}/api/v1/servers?${sp}`, {
      signal: AbortSignal.timeout(4000),
      next: { revalidate: 3600 },
    });
    if (!res.ok)
      return { servers: [], pagination: { total: 0, page: 1, limit: 25, pages: 0 } };
    const data = await res.json();
    return {
      servers: data.data || [],
      pagination: data.pagination || { total: 0, page: 1, limit: 25, pages: 0 },
    };
  } catch {
    return { servers: [], pagination: { total: 0, page: 1, limit: 25, pages: 0 } };
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function scoreClass(score: number | null): string {
  if (score === null) return "score-unscanned";
  if (score >= 80) return "score-good";
  if (score >= 60) return "score-moderate";
  if (score >= 40) return "score-poor";
  return "score-critical";
}

function fmtNum(n: number | null | undefined): string {
  if (n == null) return "—";
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return n.toLocaleString();
}

function avgScore(servers: Server[]): number | null {
  const scanned = servers.filter((s) => s.latest_score !== null);
  if (scanned.length === 0) return null;
  return Math.round(scanned.reduce((s, srv) => s + (srv.latest_score ?? 0), 0) / scanned.length);
}

function buildPageUrl(
  category: string,
  sp: Record<string, string | undefined>,
  page: number
): string {
  const params = new URLSearchParams();
  if (sp.sort && sp.sort !== "score") params.set("sort", sp.sort);
  if (sp.order && sp.order !== "desc") params.set("order", sp.order);
  if (sp.min_score) params.set("min_score", sp.min_score);
  if (page > 1) params.set("page", String(page));
  const qs = params.toString();
  return qs ? `/categories/${category}?${qs}` : `/categories/${category}`;
}

// ── SVG Icons (duplicated so this file is self-contained) ─────────────────────

function DatabaseIcon() {
  return (
    <svg width="22" height="22" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <ellipse cx="10" cy="5" rx="7" ry="2.5" />
      <path d="M3 5v4c0 1.38 3.13 2.5 7 2.5S17 10.38 17 9V5" />
      <path d="M3 9v4c0 1.38 3.13 2.5 7 2.5S17 14.38 17 13V9" />
    </svg>
  );
}
function FilesystemIcon() {
  return (
    <svg width="22" height="22" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M3 6a1 1 0 011-1h4l2 2h6a1 1 0 011 1v7a1 1 0 01-1 1H4a1 1 0 01-1-1V6z" />
    </svg>
  );
}
function ApiIcon() {
  return (
    <svg width="22" height="22" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="7" width="5" height="6" rx="1" />
      <rect x="13" y="7" width="5" height="6" rx="1" />
      <path d="M7 10h6" />
      <path d="M10 7V4" />
      <path d="M10 16v-3" />
    </svg>
  );
}
function DevToolsIcon() {
  return (
    <svg width="22" height="22" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="5 8 2 10 5 12" />
      <polyline points="15 8 18 10 15 12" />
      <line x1="11" y1="5" x2="9" y2="15" />
    </svg>
  );
}
function AiMlIcon() {
  return (
    <svg width="22" height="22" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round">
      <circle cx="10" cy="10" r="2" />
      <circle cx="4"  cy="6"  r="1.4" />
      <circle cx="16" cy="6"  r="1.4" />
      <circle cx="4"  cy="14" r="1.4" />
      <circle cx="16" cy="14" r="1.4" />
      <line x1="5.2"  y1="6.8"  x2="8.5"  y2="9.2" />
      <line x1="14.8" y1="6.8"  x2="11.5" y2="9.2" />
      <line x1="5.2"  y1="13.2" x2="8.5"  y2="10.8" />
      <line x1="14.8" y1="13.2" x2="11.5" y2="10.8" />
    </svg>
  );
}
function CommunicationIcon() {
  return (
    <svg width="22" height="22" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M17 10c0 3.31-3.13 6-7 6a7.87 7.87 0 01-3-.58L3 17l1.07-3.07A5.78 5.78 0 013 10c0-3.31 3.13-6 7-6s7 2.69 7 6z" />
    </svg>
  );
}
function CloudInfraIcon() {
  return (
    <svg width="22" height="22" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M16 13.5a3.5 3.5 0 00-3.5-3.5 3.5 3.5 0 00-3.4-2.7 3.5 3.5 0 00-3.5 3.5H5a2.5 2.5 0 000 5h10.5a2.5 2.5 0 000-5H16z" />
    </svg>
  );
}
function SecurityIcon() {
  return (
    <svg width="22" height="22" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10 2L17 5v5c0 4.5-3 8-7 9.5C6 18 3 14.5 3 10V5l7-3z" />
      <polyline points="7 10 9 12 13 8" />
    </svg>
  );
}
function DataProcessingIcon() {
  return (
    <svg width="22" height="22" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="3 6 10 3 17 6" />
      <line x1="10" y1="3" x2="10" y2="11" />
      <path d="M5 8.5v5l5 2.5 5-2.5v-5" />
    </svg>
  );
}
function MonitoringIcon() {
  return (
    <svg width="22" height="22" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="3 14 7 9 10 12 13 7 17 11" />
      <rect x="2" y="3" width="16" height="14" rx="1.5" />
    </svg>
  );
}
function SearchIcon() {
  return (
    <svg width="22" height="22" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
      <circle cx="8.5" cy="8.5" r="5.5" />
      <path d="M13.5 13.5L17 17" />
    </svg>
  );
}
function BrowserWebIcon() {
  return (
    <svg width="22" height="22" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="10" cy="10" r="7.5" />
      <path d="M2.5 10h15" />
      <path d="M10 2.5c-2 2.5-2 12.5 0 15" />
      <path d="M10 2.5c2 2.5 2 12.5 0 15" />
    </svg>
  );
}
function CodeExecutionIcon() {
  return (
    <svg width="22" height="22" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="6 8 2 12 6 16" />
      <polyline points="14 8 18 12 14 16" />
      <line x1="11" y1="6" x2="9" y2="18" />
    </svg>
  );
}
function OtherIcon() {
  return (
    <svg width="22" height="22" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
      <circle cx="5"  cy="5"  r="1.5" />
      <circle cx="10" cy="5"  r="1.5" />
      <circle cx="15" cy="5"  r="1.5" />
      <circle cx="5"  cy="10" r="1.5" />
      <circle cx="10" cy="10" r="1.5" />
      <circle cx="15" cy="10" r="1.5" />
      <circle cx="5"  cy="15" r="1.5" />
      <circle cx="10" cy="15" r="1.5" />
      <circle cx="15" cy="15" r="1.5" />
    </svg>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

const SORT_OPTIONS = [
  { value: "score", label: "Score" },
  { value: "stars", label: "Stars" },
  { value: "downloads", label: "Downloads" },
  { value: "name", label: "Name" },
  { value: "updated", label: "Last Updated" },
];

export default async function CategoryPage({
  params,
  searchParams,
}: {
  params: Promise<{ category: string }>;
  searchParams: Promise<{
    sort?: string;
    order?: string;
    page?: string;
    min_score?: string;
  }>;
}) {
  const { category } = await params;
  const sp = await searchParams;

  // Validate category
  if (!CATEGORIES.includes(category as CategorySlug)) notFound();
  const meta = CATEGORY_META[category as CategorySlug];

  const page = Number(sp.page || 1);
  const { servers, pagination } = await getCategoryServers({
    category,
    sort: sp.sort,
    order: sp.order,
    page,
    min_score: sp.min_score,
  });

  const avg = avgScore(servers);
  const scannedCount = servers.filter((s) => s.latest_score !== null).length;
  const criticalCount = servers.filter(
    (s) => s.latest_score !== null && s.latest_score < 40
  ).length;

  const avgColor =
    avg === null
      ? "var(--text-3)"
      : avg >= 80
        ? "var(--good)"
        : avg >= 60
          ? "var(--moderate)"
          : avg >= 40
            ? "var(--poor)"
            : "var(--critical)";

  return (
    <>
      {/* ── Breadcrumb ──────────────────────────────────────── */}
      <nav aria-label="Breadcrumb" className="breadcrumb" style={{ paddingTop: "var(--s8)" }}>
        <a href="/">Registry</a>
        <span aria-hidden="true">/</span>
        <a href="/categories">Categories</a>
        <span aria-hidden="true">/</span>
        <span style={{ color: "var(--text-2)" }}>{meta.label}</span>
      </nav>

      {/* ── Category header ─────────────────────────────────── */}
      <div className="cat-detail-header">
        <div className="cat-icon-lg" aria-hidden="true">
          {meta.icon}
        </div>
        <div>
          <h1 className="cat-detail-title">{meta.label}</h1>
          <p className="cat-detail-meta">{meta.description}</p>
          <div className="rule-count-badge" style={{ marginTop: "var(--s3)", display: "inline-flex", gap: "6px", fontFamily: "var(--font-mono)" }}>
            &#x26A0; {meta.riskNote}
          </div>
        </div>
      </div>

      {/* ── Stats strip ─────────────────────────────────────── */}
      <section className="stats-grid" aria-label="Category statistics" style={{ marginBottom: "var(--s8)" }}>
        <div className="stat-card">
          <span className="stat-value">{pagination.total.toLocaleString()}</span>
          <span className="stat-label">Total Servers</span>
        </div>
        <div className="stat-card">
          <span className="stat-value">{scannedCount.toLocaleString()}</span>
          <span className="stat-label">Scanned (this page)</span>
        </div>
        <div className="stat-card">
          <span className="stat-value" style={{ color: avgColor }}>
            {avg !== null ? (
              <>
                {avg}
                <span className="stat-value-denom">/100</span>
              </>
            ) : "—"}
          </span>
          <span className="stat-label">Avg Score (this page)</span>
        </div>
        <div className="stat-card">
          <span className="stat-value" style={{ color: criticalCount > 0 ? "var(--critical)" : "var(--good)" }}>
            {criticalCount}
          </span>
          <span className="stat-label">Critical (&lt;40)</span>
        </div>
      </section>

      {/* ── Filters ─────────────────────────────────────────── */}
      <form method="GET" action={`/categories/${category}`}>
        <div className="filter-row" style={{ marginBottom: "var(--s6)" }}>
          <span className="filter-label">Sort:</span>

          <select className="filter-select" name="sort" defaultValue={sp.sort || "score"}>
            {SORT_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                Sort by {o.label}
              </option>
            ))}
          </select>

          <select className="filter-select" name="order" defaultValue={sp.order || "desc"}>
            <option value="desc">Descending</option>
            <option value="asc">Ascending</option>
          </select>

          <select className="filter-select" name="min_score" defaultValue={sp.min_score || ""}>
            <option value="">Any score</option>
            <option value="80">Good (80+)</option>
            <option value="60">Moderate (60+)</option>
            <option value="40">Poor (40+)</option>
          </select>

          <button type="submit" className="btn-primary btn-primary-sm">
            Apply
          </button>

          <span className="result-count">
            {pagination.total.toLocaleString()} server{pagination.total !== 1 ? "s" : ""}
          </span>
        </div>
      </form>

      {/* ── Server table ────────────────────────────────────── */}
      {servers.length === 0 ? (
        <div className="empty-state">
          <h3>No servers found</h3>
          <p>
            {pagination.total === 0
              ? `No ${meta.label} servers have been indexed yet.`
              : "No servers match the current filters."}
          </p>
          <a href={`/categories/${category}`} style={{ marginTop: "var(--s4)", display: "inline-block", fontSize: "14px" }}>
            Clear filters
          </a>
        </div>
      ) : (
        <table className="data-table" aria-label={`${meta.label} MCP servers`}>
          <thead>
            <tr>
              <th>Server</th>
              <th>Language</th>
              <th className="right">Stars</th>
              <th className="right">Downloads</th>
              <th className="right">Score</th>
            </tr>
          </thead>
          <tbody>
            {servers.map((server) => (
              <tr key={server.id}>
                <td>
                  <a href={`/server/${server.slug}`} className="server-name-link">
                    {server.name}
                  </a>
                  {server.description && (
                    <p className="server-desc">{server.description}</p>
                  )}
                  {server.author && (
                    <p className="server-author">
                      by {server.author}
                    </p>
                  )}
                </td>
                <td className="server-lang">
                  {server.language || "\u2014"}
                </td>
                <td className="right server-metric">
                  {fmtNum(server.github_stars)}
                </td>
                <td className="right server-metric">
                  {fmtNum(server.npm_downloads)}
                </td>
                <td className="right">
                  <span className={`score-badge ${scoreClass(server.latest_score)}`}>
                    {server.latest_score === null ? "Unscanned" : server.latest_score}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {/* ── Pagination ──────────────────────────────────────── */}
      {pagination.pages > 1 && (
        <nav className="pagination" aria-label="Page navigation">
          {page > 1 && (
            <a
              href={buildPageUrl(category, sp, page - 1)}
              className="page-btn"
              aria-label="Previous page"
            >
              ←
            </a>
          )}
          {Array.from({ length: Math.min(pagination.pages, 7) }, (_, i) => {
            const p = i + 1;
            return (
              <a
                key={p}
                href={buildPageUrl(category, sp, p)}
                className={`page-btn${p === page ? " active" : ""}`}
                aria-current={p === page ? "page" : undefined}
              >
                {p}
              </a>
            );
          })}
          {pagination.pages > 7 && page < pagination.pages && (
            <>
              <span className="pagination-ellipsis">&hellip;</span>
              <a href={buildPageUrl(category, sp, pagination.pages)} className="page-btn">
                {pagination.pages}
              </a>
            </>
          )}
          {page < pagination.pages && (
            <a
              href={buildPageUrl(category, sp, page + 1)}
              className="page-btn"
              aria-label="Next page"
            >
              →
            </a>
          )}
        </nav>
      )}

      {/* ── Footer nav ──────────────────────────────────────── */}
      <div className="page-footer-nav">
        <a href="/categories" className="page-footer-link">
          <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
            <path d="M10 3L5 8l5 5" />
          </svg>
          All categories
        </a>
        <a href="/" className="page-footer-link">Search all servers</a>
      </div>
    </>
  );
}
