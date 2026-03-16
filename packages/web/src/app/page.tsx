import type { Metadata } from "next";

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
    color: "#1a1a1a",
    textColor: "#1a1a1a",
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

function CategoryChip({ cat }: { cat: string | null }) {
  if (!cat) return <span className="text-muted">—</span>;
  return <span className="category-chip">{cat}</span>;
}

function FeaturedOrgCard({ org }: { org: (typeof FEATURED_ORGS)[0] }) {
  return (
    <a href={`/server/${org.slug}`} className="featured-card" style={{ paddingTop: 0, overflow: "hidden" }}>
      {/* Brand color top bar */}
      <div style={{ height: "3px", background: org.color, margin: "0 calc(-1 * var(--s5)) var(--s4)", marginTop: 0, borderRadius: 0 }} />
      <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "var(--s2)" }}>
        <div style={{
          width: "32px",
          height: "32px",
          borderRadius: "8px",
          background: `${org.color}18`,
          border: `1px solid ${org.color}30`,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          fontSize: "10px",
          fontWeight: 800,
          letterSpacing: "0.05em",
          color: org.textColor,
          flexShrink: 0,
          fontFamily: "monospace",
        }}>
          {org.initials}
        </div>
        <span style={{ fontSize: "11px", fontWeight: 600, color: "var(--text-3)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
          {org.org}
        </span>
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
          <span style={{ color: "var(--poor)", fontWeight: 700, fontSize: "16px", lineHeight: "1" }}>!</span>
          <span>
            Unable to reach the API. Showing cached data where available.
            If this persists, check <code style={{ fontSize: "12px" }}>NEXT_PUBLIC_API_URL</code>.
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
          103 detection rules. Zero guesswork.
        </p>
      </section>

      {/* ── Stats strip ───────────────────────────────── */}
      <section
        style={{
          display: "flex",
          alignItems: "baseline",
          gap: "10px",
          flexWrap: "wrap",
          marginBottom: "var(--s8)",
          padding: "var(--s5) var(--s6)",
          background: "var(--surface)",
          border: "1px solid var(--border)",
          borderRadius: "var(--r-lg)",
          boxShadow: "var(--shadow-card)",
        }}
        aria-label="Ecosystem statistics"
      >
        <span
          style={{
            fontFamily: "'Outfit Variable','Outfit',system-ui,sans-serif",
            fontSize: "36px",
            fontWeight: 700,
            letterSpacing: "-0.04em",
            color: "var(--text)",
            lineHeight: 1,
          }}
        >
          {stats ? stats.total_servers.toLocaleString() : "—"}
        </span>
        <span
          style={{
            fontSize: "15px",
            fontWeight: 500,
            color: "var(--text-2)",
          }}
        >
          unique MCP servers indexed
        </span>
        {stats && stats.total_scanned > 0 && (
          <span
            style={{
              marginLeft: "auto",
              fontSize: "12px",
              color: "var(--text-3)",
            }}
          >
            {stats.total_scanned.toLocaleString()} scanned · avg score{" "}
            <strong style={{ color: avgScoreColor, fontWeight: 600 }}>
              {stats.average_score ?? 0}
            </strong>
            /100 · 103 rules
          </span>
        )}
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

          <input
            className="filter-select"
            type="text"
            name="author"
            style={{ width: "140px" }}
            defaultValue={sp.author || ""}
            placeholder="by owner…"
            autoComplete="off"
          />

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

          <button
            type="submit"
            className="btn-primary"
            style={{ padding: "7px 16px", fontSize: "13px" }}
          >
            Search
          </button>

          <span className="result-count">
            {pagination.total.toLocaleString()} server
            {pagination.total !== 1 ? "s" : ""}
          </span>
        </div>
      </form>

      {/* ── Server Table ──────────────────────────────── */}
      {servers.length === 0 ? (
        <div className="empty-state">
          <h3>No servers found</h3>
          <p>Try a different search term or remove filters.</p>
        </div>
      ) : (
        <table className="data-table" aria-label="MCP server registry">
          <thead>
            <tr>
              <th>Server</th>
              <th>Category</th>
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
                  <a
                    href={`/server/${server.slug}`}
                    className="server-name-link"
                  >
                    {server.name}
                  </a>
                  {server.description && (
                    <p className="server-desc">{server.description}</p>
                  )}
                  {server.author && (
                    <p
                      style={{
                        color: "var(--text-3)",
                        fontSize: "11px",
                        marginTop: "2px",
                      }}
                    >
                      by {server.author}
                    </p>
                  )}
                </td>
                <td>
                  <CategoryChip cat={server.category} />
                </td>
                <td style={{ color: "var(--text-3)", fontSize: "13px" }}>
                  {server.language || "—"}
                </td>
                <td
                  className="right"
                  style={{ color: "var(--text-2)", fontSize: "13px" }}
                >
                  {fmtNum(server.github_stars)}
                </td>
                <td
                  className="right"
                  style={{ color: "var(--text-2)", fontSize: "13px" }}
                >
                  {fmtNum(server.npm_downloads)}
                </td>
                <td className="right">
                  <ScoreBadge score={server.latest_score} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
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
              <span
                style={{ color: "var(--text-3)", fontSize: "14px" }}
              >
                …
              </span>
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
