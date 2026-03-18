import type { Metadata } from "next";

export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "MCP Server Security Registry",
  description:
    "Search thousands of MCP servers. Compare security scores. Evaluate the safety of every Model Context Protocol integration before you deploy.",
};

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
  tool_count: number;
  connection_status: "success" | "failed" | "timeout" | "no_endpoint" | null;
  github_url: string | null;
  npm_package: string | null;
  pypi_package: string | null;
}

interface Pagination {
  total: number;
  page: number;
  limit: number;
  pages: number;
}

interface EcosystemStats {
  total_servers: number;
  total_scanned: number;
  average_score: number;
  category_breakdown: Record<string, number>;
  severity_breakdown: Record<string, number>;
  score_distribution: Array<{ range: string; count: number }>;
}

// ── Data fetching ─────────────────────────────────────────────────────────────

async function getServers(params: {
  q?: string;
  author?: string;
  category?: string;
  sort?: string;
  order?: string;
  page?: number;
  min_score?: string;
}): Promise<{ servers: Server[]; pagination: Pagination }> {
  try {
    const sp = new URLSearchParams();
    sp.set("limit", "25");
    sp.set("sort", params.sort || "score");
    sp.set("order", params.order || "desc");
    const searchQ = [params.q, params.author].filter(Boolean).join(" ");
    if (searchQ) sp.set("q", searchQ);
    if (params.category && params.category !== "all")
      sp.set("category", params.category);
    if (params.page && params.page > 1) sp.set("page", String(params.page));
    if (params.min_score) sp.set("min_score", params.min_score);

    const res = await fetch(`${API_URL}/api/v1/servers?${sp}`, {
      signal: AbortSignal.timeout(4000),
    });
    if (!res.ok) return { servers: [], pagination: { total: 0, page: 1, limit: 25, pages: 0 } };
    const data = await res.json();
    return {
      servers: data.data || [],
      pagination: data.pagination || { total: 0, page: 1, limit: 25, pages: 0 },
    };
  } catch {
    return { servers: [], pagination: { total: 0, page: 1, limit: 25, pages: 0 } };
  }
}

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

function connectionLabel(status: Server["connection_status"]): { text: string; cls: string } {
  switch (status) {
    case "success": return { text: "Online", cls: "conn-online" };
    case "failed": return { text: "Offline", cls: "conn-offline" };
    case "timeout": return { text: "Timeout", cls: "conn-offline" };
    default: return { text: "Unknown", cls: "conn-unknown" };
  }
}

function sourceOrigin(server: Server): { label: string; icon: string } | null {
  if (server.npm_package) return { label: "npm", icon: "npm" };
  if (server.pypi_package) return { label: "PyPI", icon: "pypi" };
  if (server.github_url) return { label: "GitHub", icon: "github" };
  return null;
}

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
];

const SORT_OPTIONS = [
  { value: "score", label: "Score" },
  { value: "stars", label: "Stars" },
  { value: "downloads", label: "Downloads" },
  { value: "name", label: "Name" },
  { value: "updated", label: "Last Updated" },
];

// ── Official org featured servers ────────────────────────────────────────────
const FEATURED_ORGS: Array<{
  name: string;
  org: string;
  slug: string;
  desc: string;
  color: string;
  textColor: string;
  initials: string;
}> = [
  {
    name: "GitHub MCP Server",
    org: "GitHub",
    slug: "github-mcp-server",
    desc: "Official GitHub server — repos, issues, PRs, code search, Actions.",
    color: "#0969da",
    textColor: "#0969da",
    initials: "GH",
  },
  {
    name: "Stripe Agent Toolkit",
    org: "Stripe",
    slug: "stripe-agent-toolkit",
    desc: "Official Stripe server — payments, customers, invoices, subscriptions.",
    color: "#635BFF",
    textColor: "#635BFF",
    initials: "ST",
  },
  {
    name: "Cloudflare MCP Server",
    org: "Cloudflare",
    slug: "mcp-server-cloudflare",
    desc: "Official Cloudflare server — Workers, R2, KV, D1, Durable Objects.",
    color: "#F6821F",
    textColor: "#e06a0a",
    initials: "CF",
  },
  {
    name: "Linear MCP",
    org: "Linear",
    slug: "linear-mcp",
    desc: "Official Linear server — issues, projects, cycles, teams.",
    color: "#5E6AD2",
    textColor: "#5E6AD2",
    initials: "LN",
  },
  {
    name: "Notion MCP",
    org: "Notion",
    slug: "notion-mcp",
    desc: "Official Notion server — pages, databases, blocks, search.",
    color: "#9CA3AF",
    textColor: "#9CA3AF",
    initials: "NT",
  },
  {
    name: "Atlassian Remote MCP",
    org: "Atlassian",
    slug: "atlassian-remote-mcp-server",
    desc: "Official Atlassian server — Jira issues, Confluence pages, Bitbucket.",
    color: "#0052CC",
    textColor: "#0052CC",
    initials: "AT",
  },
];

// ── Components ────────────────────────────────────────────────────────────────

function ScoreBadge({ score }: { score: number | null }) {
  const cls = scoreClass(score);
  return (
    <span className={`score-badge ${cls}`}>
      {score === null ? "Unscanned" : score}
    </span>
  );
}

function FeaturedOrgCard({ org }: { org: (typeof FEATURED_ORGS)[0] }) {
  return (
    <a href={`/server/${org.slug}`} className="featured-card" style={{ paddingTop: 0 }}>
      <div className="featured-brand-bar" style={{ background: org.color }} />
      <div className="featured-brand-row">
        <div
          className="featured-brand-icon"
          style={{
            background: `${org.color}18`,
            border: `1px solid ${org.color}30`,
            color: org.textColor,
          }}
        >
          {org.initials}
        </div>
        <span className="featured-brand-label">{org.org}</span>
      </div>
      <div className="featured-card-name">{org.name}</div>
      <div className="featured-card-desc">{org.desc}</div>
    </a>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default async function HomePage({
  searchParams,
}: {
  searchParams: Promise<{
    q?: string;
    author?: string;
    category?: string;
    sort?: string;
    order?: string;
    page?: string;
    min_score?: string;
  }>;
}) {
  const sp = await searchParams;
  const page = Number(sp.page || 1);

  const isFiltered =
    !!sp.q ||
    !!sp.author ||
    (!!sp.category && sp.category !== "all") ||
    !!sp.min_score;

  const [{ servers, pagination }, stats] = await Promise.all([
    getServers({
      q: sp.q,
      author: sp.author,
      category: sp.category,
      sort: sp.sort,
      order: sp.order,
      page,
      min_score: sp.min_score,
    }),
    getStats(),
  ]);

  const avgScoreColor =
    stats && stats.average_score >= 80
      ? "var(--good)"
      : stats && stats.average_score >= 60
        ? "var(--moderate)"
        : stats && stats.average_score >= 40
          ? "var(--poor)"
          : "var(--critical)";

  const apiDown = !stats && servers.length === 0;

  return (
    <>
      {/* ── API warning ──────────────────────────────── */}
      {apiDown && (
        <div role="alert" className="api-alert">
          <span className="api-alert-icon">!</span>
          <span>
            Unable to reach the API. Showing cached data where available.
            If this persists, check <code>NEXT_PUBLIC_API_URL</code>.
          </span>
        </div>
      )}

      {/* ── Hero ──────────────────────────────────────── */}
      <section className="hero">
        <div className="hero-eyebrow">
          <svg width="12" height="12" viewBox="0 0 16 16" fill="none">
            <path
              d="M8 1L14 4V8C14 11.5 11.5 14.5 8 15.5C4.5 14.5 2 11.5 2 8V4L8 1Z"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinejoin="round"
              fill="none"
            />
          </svg>
          Security Intelligence Registry
        </div>
        <h1 className="hero-title">
          Trust Every MCP Server
          <br />
          Before It Touches <em>Your Agent</em>
        </h1>
        <p className="hero-sub">
          {stats?.total_servers
            ? `${stats.total_servers.toLocaleString()} MCP servers discovered across ${Object.keys(stats.category_breakdown || {}).length} categories.`
            : "22,000+ MCP servers discovered across the ecosystem."}{" "}
          150+ detection rules. Zero guesswork.
        </p>
      </section>

      {/* ── Stats Cards ──────────────────────────────── */}
      <section className="stats-cards" aria-label="Ecosystem statistics">
        {/* Card 1 — Dark: total servers */}
        <div className="stats-card stats-card-dark">
          <div className="stats-card-dark-glow" aria-hidden="true" />
          <span className="stats-card-big-num">
            {stats ? stats.total_servers.toLocaleString() : "\u2014"}
          </span>
          <span className="stats-card-subtitle">MCP servers discovered and scored</span>
          <div className="stats-card-sub-row">
            <div className="stats-card-sub-item">
              <span className="stats-card-sub-num">
                {stats ? stats.total_scanned.toLocaleString() : "\u2014"}
              </span>
              <span className="stats-card-sub-label">Scanned</span>
            </div>
            <div className="stats-card-sub-item">
              <span className="stats-card-sub-num">150+</span>
              <span className="stats-card-sub-label">Rules</span>
            </div>
            <div className="stats-card-sub-item">
              <span className="stats-card-sub-num">
                {stats ? Object.keys(stats.category_breakdown || {}).length : "\u2014"}
              </span>
              <span className="stats-card-sub-label">Categories</span>
            </div>
          </div>
        </div>

        {/* Card 2 — White: avg trust score ring */}
        <div className="stats-card stats-card-score">
          <div className="stats-card-ring-wrap">
            <svg width="120" height="120" viewBox="0 0 120 120" className="stats-card-ring" aria-hidden="true">
              <circle cx="60" cy="60" r="48" fill="none" stroke="#E5E7EB" strokeWidth="8" />
              <circle
                cx="60"
                cy="60"
                r="48"
                fill="none"
                stroke={avgScoreColor}
                strokeWidth="8"
                strokeLinecap="round"
                strokeDasharray={2 * Math.PI * 48}
                strokeDashoffset={2 * Math.PI * 48 * (1 - (stats?.average_score ?? 0) / 100)}
                style={{ transform: "rotate(-90deg)", transformOrigin: "center" }}
              />
            </svg>
            <span className="stats-card-ring-num" style={{ color: avgScoreColor }}>
              {stats?.average_score ?? "\u2014"}
            </span>
          </div>
          <span className="stats-card-ring-label">Avg Trust Score</span>
        </div>

        {/* Card 3 — Green: detection rules */}
        <div className="stats-card stats-card-green">
          <span className="stats-card-big-num">150+</span>
          <span className="stats-card-subtitle">Detection Rules</span>
          <span className="stats-card-green-detail">Deterministic &middot; No LLMs &middot; No false positives</span>
        </div>
      </section>

      {/* ── Featured Official Servers ─────────────────── */}
      {!isFiltered && (
        <section className="featured-section" aria-label="Official server integrations">
          <div className="featured-header">
            <h2 className="featured-heading">Official Integrations</h2>
            <a href="/?sort=score&order=desc" className="featured-view-all">
              Browse all →
            </a>
          </div>
          <div className="featured-grid">
            {FEATURED_ORGS.map((org) => (
              <FeaturedOrgCard key={org.slug} org={org} />
            ))}
          </div>
        </section>
      )}

      {/* ── Search + Filters ──────────────────────────── */}
      <form method="GET" action="/">
        <div className="search-bar">
          <span className="search-icon" aria-hidden="true">
            <svg
              width="16"
              height="16"
              viewBox="0 0 20 20"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.8"
              strokeLinecap="round"
            >
              <circle cx="8.5" cy="8.5" r="5.5" />
              <path d="M13.5 13.5L17 17" />
            </svg>
          </span>
          <input
            className="search-input"
            type="search"
            name="q"
            defaultValue={sp.q || ""}
            placeholder="Search by name, author, or description…"
            autoComplete="off"
          />
        </div>

        <div className="filter-row">
          <span className="filter-label">Filter:</span>

          <select
            className="filter-select"
            name="category"
            defaultValue={sp.category || "all"}
          >
            <option value="all">All categories</option>
            {CATEGORIES.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>

          <select
            className="filter-select"
            name="min_score"
            defaultValue={sp.min_score || ""}
          >
            <option value="">Any score</option>
            <option value="80">Good (80+)</option>
            <option value="60">Moderate (60+)</option>
            <option value="40">Poor (40+)</option>
          </select>

          <label className="author-filter">
            <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
              <circle cx="8" cy="5.5" r="2.5" />
              <path d="M3 13c0-2.76 2.24-5 5-5s5 2.24 5 5" />
            </svg>
            <span className="author-filter-label">Owner</span>
            <input
              type="text"
              name="author"
              className="author-filter-input"
              defaultValue={sp.author || ""}
              placeholder="any\u2026"
              autoComplete="off"
            />
          </label>

          <select
            className="filter-select"
            name="sort"
            defaultValue={sp.sort || "score"}
          >
            {SORT_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                Sort by {o.label}
              </option>
            ))}
          </select>

          <select
            className="filter-select"
            name="order"
            defaultValue={sp.order || "desc"}
          >
            <option value="desc">Descending</option>
            <option value="asc">Ascending</option>
          </select>

          <button type="submit" className="btn-primary btn-primary-sm">
            Search
          </button>

          <span className="result-count">
            {pagination.total.toLocaleString()} server
            {pagination.total !== 1 ? "s" : ""}
          </span>
        </div>
      </form>

      {/* ── Server List ──────────────────────────────── */}
      {servers.length === 0 ? (
        <div className="empty-state">
          <h3>No servers found</h3>
          <p>Try a different search term or remove filters.</p>
        </div>
      ) : (
        <div className="server-list" aria-label="MCP server registry">
          {servers.map((server) => (
            <a
              key={server.id}
              href={`/server/${server.slug}`}
              className="server-row"
            >
              <div className="server-row-main">
                <div className="server-row-header">
                  <span className="server-row-name">{server.name}</span>
                  <ScoreBadge score={server.latest_score} />
                </div>
                {server.description && (
                  <p className="server-row-desc">{server.description}</p>
                )}
                <div className="server-row-meta">
                  {server.author && (
                    <span className="server-meta-chip">
                      <svg width="11" height="11" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
                        <circle cx="8" cy="5.5" r="2.5" />
                        <path d="M3 13c0-2.76 2.24-5 5-5s5 2.24 5 5" />
                      </svg>
                      {server.author}
                    </span>
                  )}
                  {/* Tool count */}
                  {server.tool_count > 0 && (
                    <span className="server-meta-chip">
                      <svg width="11" height="11" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M9.5 2.5L13 6l-7 7-4 1 1-4 7-7z" />
                      </svg>
                      {server.tool_count} tool{server.tool_count !== 1 ? "s" : ""}
                    </span>
                  )}
                  {/* Connection status */}
                  {(() => {
                    const conn = connectionLabel(server.connection_status);
                    return (
                      <span className={`server-meta-chip ${conn.cls}`}>
                        <span className="conn-dot" />
                        {conn.text}
                      </span>
                    );
                  })()}
                  {/* Source origin */}
                  {(() => {
                    const origin = sourceOrigin(server);
                    return origin ? (
                      <span className="server-meta-chip server-meta-origin">
                        {origin.label}
                      </span>
                    ) : null;
                  })()}
                  {/* Language */}
                  {server.language && (
                    <span className="server-meta-chip">
                      <svg width="10" height="10" viewBox="0 0 16 16" fill="currentColor" opacity="0.5">
                        <circle cx="8" cy="8" r="4" />
                      </svg>
                      {server.language}
                    </span>
                  )}
                  {server.category && (
                    <span className="server-meta-chip server-meta-cat">
                      {server.category}
                    </span>
                  )}
                  {server.github_stars != null && server.github_stars > 0 && (
                    <span className="server-meta-chip">
                      <svg width="11" height="11" viewBox="0 0 16 16" fill="currentColor">
                        <path d="M8 .25a.75.75 0 01.673.418l1.882 3.815 4.21.612a.75.75 0 01.416 1.279l-3.046 2.97.719 4.192a.75.75 0 01-1.088.791L8 12.347l-3.766 1.98a.75.75 0 01-1.088-.79l.72-4.194L.818 6.374a.75.75 0 01.416-1.28l4.21-.611L7.327.668A.75.75 0 018 .25z" />
                      </svg>
                      {fmtNum(server.github_stars)}
                    </span>
                  )}
                  {server.npm_downloads != null && server.npm_downloads > 0 && (
                    <span className="server-meta-chip">
                      <svg width="11" height="11" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
                        <path d="M8 2v8M5 7l3 3 3-3M3 13h10" />
                      </svg>
                      {fmtNum(server.npm_downloads)}
                    </span>
                  )}
                </div>
              </div>
            </a>
          ))}
        </div>
      )}

      {/* ── Pagination ────────────────────────────────── */}
      {pagination.pages > 1 && (
        <nav className="pagination" aria-label="Page navigation">
          {page > 1 && (
            <a
              href={buildPageUrl(sp, page - 1)}
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
                href={buildPageUrl(sp, p)}
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
              <a
                href={buildPageUrl(sp, pagination.pages)}
                className="page-btn"
              >
                {pagination.pages}
              </a>
            </>
          )}
          {page < pagination.pages && (
            <a
              href={buildPageUrl(sp, page + 1)}
              className="page-btn"
              aria-label="Next page"
            >
              →
            </a>
          )}
        </nav>
      )}
    </>
  );
}

function buildPageUrl(
  sp: Record<string, string | undefined>,
  page: number
): string {
  const params = new URLSearchParams();
  if (sp.q) params.set("q", sp.q);
  if (sp.author) params.set("author", sp.author);
  if (sp.category && sp.category !== "all") params.set("category", sp.category);
  if (sp.sort && sp.sort !== "score") params.set("sort", sp.sort);
  if (sp.order && sp.order !== "desc") params.set("order", sp.order);
  if (sp.min_score) params.set("min_score", sp.min_score);
  if (page > 1) params.set("page", String(page));
  const qs = params.toString();
  return qs ? `/?${qs}` : "/";
}
