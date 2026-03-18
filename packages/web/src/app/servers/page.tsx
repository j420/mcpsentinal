import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Browse MCP Servers",
  description:
    "Browse and search thousands of MCP servers. Filter by category, score, and language. View detailed security analysis for every server.",
};

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

// ── Data fetching ─────────────────────────────────────────────────────────────

async function getServers(params: {
  q?: string;
  category?: string;
  sort?: string;
  order?: string;
  page?: number;
  min_score?: string;
}): Promise<{ servers: Server[]; pagination: Pagination }> {
  try {
    const sp = new URLSearchParams();
    sp.set("limit", "24");
    sp.set("sort", params.sort || "score");
    sp.set("order", params.order || "desc");
    if (params.q) sp.set("q", params.q);
    if (params.category && params.category !== "all")
      sp.set("category", params.category);
    if (params.page && params.page > 1) sp.set("page", String(params.page));
    if (params.min_score) sp.set("min_score", params.min_score);

    const res = await fetch(`${API_URL}/api/v1/servers?${sp}`, {
      signal: AbortSignal.timeout(4000),
    });
    if (!res.ok)
      return {
        servers: [],
        pagination: { total: 0, page: 1, limit: 24, pages: 0 },
      };
    const data = await res.json();
    return {
      servers: data.data || [],
      pagination: data.pagination || { total: 0, page: 1, limit: 24, pages: 0 },
    };
  } catch {
    return {
      servers: [],
      pagination: { total: 0, page: 1, limit: 24, pages: 0 },
    };
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

function scoreRating(score: number | null): string {
  if (score === null) return "Unscanned";
  if (score >= 80) return "Good";
  if (score >= 60) return "Moderate";
  if (score >= 40) return "Poor";
  return "Critical";
}

function fmtNum(n: number | null | undefined): string {
  if (n == null) return "\u2014";
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

// ── Page ──────────────────────────────────────────────────────────────────────

export default async function ServersPage({
  searchParams,
}: {
  searchParams: Promise<{
    q?: string;
    category?: string;
    sort?: string;
    order?: string;
    page?: string;
    min_score?: string;
  }>;
}) {
  const sp = await searchParams;
  const page = Number(sp.page || 1);

  const { servers, pagination } = await getServers({
    q: sp.q,
    category: sp.category,
    sort: sp.sort,
    order: sp.order,
    page,
    min_score: sp.min_score,
  });

  return (
    <div className="servers-page">
      {/* Page Header */}
      <div className="servers-page-header">
        <h1 className="servers-page-title">MCP Server Registry</h1>
        <p className="servers-page-sub">
          Browse {pagination.total > 0 ? pagination.total.toLocaleString() : ""} servers scanned across 150+ security rules
        </p>
      </div>

      {/* Search + Filters */}
      <form method="GET" action="/servers" className="servers-filters">
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
            placeholder="Search servers by name, author, or description..."
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

          <select
            className="filter-select"
            name="sort"
            defaultValue={sp.sort || "score"}
          >
            {SORT_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                Sort: {o.label}
              </option>
            ))}
          </select>

          <select
            className="filter-select"
            name="order"
            defaultValue={sp.order || "desc"}
          >
            <option value="desc">Desc</option>
            <option value="asc">Asc</option>
          </select>

          <button type="submit" className="btn-primary btn-primary-sm">
            Search
          </button>

          <span className="result-count">
            {pagination.total.toLocaleString()} result{pagination.total !== 1 ? "s" : ""}
          </span>
        </div>
      </form>

      {/* Server Card Grid */}
      {servers.length === 0 ? (
        <div className="empty-state">
          <h3>No servers found</h3>
          <p>Try a different search term or remove filters.</p>
        </div>
      ) : (
        <div className="srv-card-grid">
          {servers.map((server) => (
            <a
              key={server.id}
              href={`/servers/${server.slug}`}
              className="srv-card"
            >
              {/* Score indicator stripe */}
              <div className={`srv-card-score-stripe srv-stripe-${scoreRating(server.latest_score).toLowerCase()}`} />

              <div className="srv-card-inner">
                {/* Top row: name + score */}
                <div className="srv-card-top">
                  <div className="srv-card-name-col">
                    <h3 className="srv-card-name">{server.name}</h3>
                    {server.author && (
                      <span className="srv-card-author">by {server.author}</span>
                    )}
                  </div>
                  <div className={`srv-card-score ${scoreClass(server.latest_score)}`}>
                    {server.latest_score !== null ? server.latest_score : "\u2014"}
                  </div>
                </div>

                {/* Description */}
                {server.description && (
                  <p className="srv-card-desc">{server.description}</p>
                )}

                {/* Footer: meta info */}
                <div className="srv-card-footer">
                  {server.category && (
                    <span className="srv-card-tag">{server.category}</span>
                  )}
                  {server.language && (
                    <span className="srv-card-meta-item">
                      <svg width="10" height="10" viewBox="0 0 16 16" fill="currentColor" opacity="0.5">
                        <circle cx="8" cy="8" r="4" />
                      </svg>
                      {server.language}
                    </span>
                  )}
                  {server.github_stars != null && server.github_stars > 0 && (
                    <span className="srv-card-meta-item">
                      <svg width="10" height="10" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
                        <path d="M8 1l2.4 4.8L16 6.6l-4 3.9.9 5.5L8 13.5 3.1 16l.9-5.5-4-3.9 5.6-.8z" />
                      </svg>
                      {fmtNum(server.github_stars)}
                    </span>
                  )}
                  {server.npm_downloads != null && server.npm_downloads > 0 && (
                    <span className="srv-card-meta-item">
                      <svg width="10" height="10" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
                        <path d="M8 2v9M4.5 7.5L8 11l3.5-3.5M2 13h12" />
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

      {/* Pagination */}
      {pagination.pages > 1 && (
        <nav className="pagination" aria-label="Page navigation">
          {page > 1 && (
            <a
              href={buildPageUrl(sp, page - 1)}
              className="page-btn"
              aria-label="Previous page"
            >
              &larr;
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
              &rarr;
            </a>
          )}
        </nav>
      )}
    </div>
  );
}

function buildPageUrl(
  sp: Record<string, string | undefined>,
  page: number
): string {
  const params = new URLSearchParams();
  if (sp.q) params.set("q", sp.q);
  if (sp.category && sp.category !== "all") params.set("category", sp.category);
  if (sp.sort && sp.sort !== "score") params.set("sort", sp.sort);
  if (sp.order && sp.order !== "desc") params.set("order", sp.order);
  if (sp.min_score) params.set("min_score", sp.min_score);
  if (page > 1) params.set("page", String(page));
  const qs = params.toString();
  return qs ? `/servers?${qs}` : "/servers";
}
