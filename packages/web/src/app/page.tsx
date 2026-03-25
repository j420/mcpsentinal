import type { Metadata } from "next";
import FeaturedCarousel from "../components/FeaturedCarousel";

export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "MCP Server Security Registry",
  description:
    "Search thousands of MCP servers. Evaluate the safety of every Model Context Protocol integration before you deploy.",
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
  last_commit: string | null;
  tool_count: number;
  connection_status: "success" | "failed" | "timeout" | "no_endpoint" | null;
  github_url: string | null;
  npm_package: string | null;
  pypi_package: string | null;
  source_names: string[];
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
  category_breakdown: Record<string, number>;
  severity_breakdown: Record<string, number>;
}

// ── Data fetching ─────────────────────────────────────────────────────────────

async function getServers(params: {
  q?: string;
  author?: string;
  category?: string;
  sort?: string;
  order?: string;
  page?: number;
}): Promise<{ servers: Server[]; pagination: Pagination }> {
  try {
    const sp = new URLSearchParams();
    sp.set("limit", "25");
    sp.set("sort", params.sort || "name");
    sp.set("order", params.order || "asc");
    const searchQ = [params.q, params.author].filter(Boolean).join(" ");
    if (searchQ) sp.set("q", searchQ);
    if (params.category && params.category !== "all")
      sp.set("category", params.category);
    if (params.page && params.page > 1) sp.set("page", String(params.page));

    const res = await fetch(`${API_URL}/api/v1/servers?${sp}`, {
      signal: AbortSignal.timeout(4000),
    });
    if (!res.ok) return { servers: [], pagination: { total: 0, page: 1, limit: 25, pages: 0 } };
    const data = await res.json();
    return {
      servers: (data.data || []).map((s: Record<string, unknown>) => ({
        ...s,
        source_names: Array.isArray(s.source_names) ? s.source_names : [],
      })),
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

function fmtNum(n: number | null | undefined): string {
  if (n == null) return "—";
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return n.toLocaleString();
}

const SOURCE_DISPLAY: Record<string, string> = {
  pulsemcp: "PulseMCP",
  smithery: "Smithery",
  npm: "npm",
  pypi: "PyPI",
  github: "GitHub",
  "official-registry": "Official",
  glama: "Glama",
  "awesome-mcp-servers": "Awesome",
  "docker-hub": "Docker",
  zarq: "Zarq",
  manual: "Manual",
  other: "Other",
};

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
  { value: "name", label: "Name" },
  { value: "stars", label: "Stars" },
  { value: "downloads", label: "Downloads" },
  { value: "updated", label: "Last Updated" },
];

// ── Brand colors for top tech orgs (used to style featured server cards) ─────
interface FeaturedOrg {
  name: string;
  org: string;
  slug: string;
  desc: string;
  color: string;
  initials: string;
}

// Brand color + initials lookup — keyed by lowercase author/org name variations
const BRAND_COLORS: Record<string, { color: string; initials: string }> = {
  github: { color: "#24292e", initials: "GH" },
  stripe: { color: "#635BFF", initials: "ST" },
  cloudflare: { color: "#F38020", initials: "CF" },
  linear: { color: "#5E6AD2", initials: "LN" },
  notion: { color: "#2D2D2D", initials: "NT" },
  atlassian: { color: "#0052CC", initials: "AT" },
  slack: { color: "#4A154B", initials: "SL" },
  google: { color: "#4285F4", initials: "GG" },
  microsoft: { color: "#00A4EF", initials: "MS" },
  aws: { color: "#FF9900", initials: "AW" },
  amazon: { color: "#FF9900", initials: "AW" },
  vercel: { color: "#1A1A1A", initials: "VC" },
  supabase: { color: "#3ECF8E", initials: "SB" },
  datadog: { color: "#632CA6", initials: "DD" },
  pagerduty: { color: "#06AC38", initials: "PD" },
  sentry: { color: "#362D59", initials: "SN" },
  mongodb: { color: "#00ED64", initials: "MG" },
  redis: { color: "#FF4438", initials: "RD" },
  twilio: { color: "#F22F46", initials: "TW" },
  sendgrid: { color: "#1A82E2", initials: "SG" },
  figma: { color: "#A259FF", initials: "FG" },
  shopify: { color: "#95BF47", initials: "SH" },
  salesforce: { color: "#00A1E0", initials: "SF" },
  hubspot: { color: "#FF7A59", initials: "HS" },
  zendesk: { color: "#03363D", initials: "ZD" },
  jira: { color: "#0052CC", initials: "JR" },
  confluence: { color: "#1868DB", initials: "CN" },
  gitlab: { color: "#FC6D26", initials: "GL" },
  bitbucket: { color: "#0052CC", initials: "BB" },
  docker: { color: "#1D63ED", initials: "DK" },
  kubernetes: { color: "#326CE5", initials: "K8" },
  hashicorp: { color: "#7B42BC", initials: "TF" },
  terraform: { color: "#7B42BC", initials: "TF" },
  snowflake: { color: "#29B5E8", initials: "SW" },
  databricks: { color: "#FF3621", initials: "DB" },
  elastic: { color: "#00BFB3", initials: "EL" },
  grafana: { color: "#F46800", initials: "GF" },
  "new relic": { color: "#008C99", initials: "NR" },
  splunk: { color: "#65A637", initials: "SP" },
  airtable: { color: "#2D7FF9", initials: "AT" },
  asana: { color: "#F06A6A", initials: "AS" },
  monday: { color: "#6C6CFF", initials: "MN" },
  okta: { color: "#007DC1", initials: "OK" },
  auth0: { color: "#EB5424", initials: "A0" },
  postman: { color: "#FF6C37", initials: "PM" },
  circleci: { color: "#343434", initials: "CI" },
  launchdarkly: { color: "#405BFF", initials: "LD" },
  prisma: { color: "#2D3748", initials: "PR" },
  planetscale: { color: "#303030", initials: "PS" },
  neon: { color: "#00E599", initials: "NE" },
  render: { color: "#46E3B7", initials: "RN" },
  "fly.io": { color: "#7B3FE4", initials: "FY" },
  anthropic: { color: "#D4A27F", initials: "AN" },
  openai: { color: "#10A37F", initials: "OA" },
  "1password": { color: "#0572EC", initials: "1P" },
  brave: { color: "#FB542B", initials: "BR" },
  browserbase: { color: "#FF6B35", initials: "BB" },
  upstash: { color: "#00E9A3", initials: "UP" },
  axiom: { color: "#2E0854", initials: "AX" },
  "e2b": { color: "#FF8800", initials: "E2" },
  firecrawl: { color: "#FF6154", initials: "FC" },
};

function lookupBrand(author: string | null): { color: string; initials: string } | null {
  if (!author) return null;
  const key = author.toLowerCase().trim();
  if (BRAND_COLORS[key]) return BRAND_COLORS[key];
  // Fuzzy: check if any brand key is contained in the author string
  for (const [bk, bv] of Object.entries(BRAND_COLORS)) {
    if (key.includes(bk) || bk.includes(key)) return bv;
  }
  return null;
}

async function getFeaturedServers(): Promise<FeaturedOrg[]> {
  try {
    // Fetch top servers sorted by stars — these tend to be the official org servers
    const res = await fetch(`${API_URL}/api/v1/servers?sort=stars&order=desc&limit=100`, {
      signal: AbortSignal.timeout(4000),
    });
    if (!res.ok) return [];
    const data = await res.json();
    const servers: Server[] = (data.data || []).map((s: Record<string, unknown>) => ({
      ...s,
      source_names: Array.isArray(s.source_names) ? s.source_names : [],
    }));

    // Filter to servers from known top-tech orgs and map to FeaturedOrg
    const featured: FeaturedOrg[] = [];
    const seenOrgs = new Set<string>();
    for (const s of servers) {
      const brand = lookupBrand(s.author);
      if (!brand) continue;
      const orgKey = (s.author ?? "").toLowerCase();
      if (seenOrgs.has(orgKey)) continue; // One server per org
      seenOrgs.add(orgKey);
      featured.push({
        name: s.name,
        org: s.author ?? s.name,
        slug: s.slug,
        desc: s.description ? (s.description.length > 80 ? s.description.slice(0, 77) + "..." : s.description) : "",
        color: brand.color,
        initials: brand.initials,
      });
    }
    return featured;
  } catch {
    return [];
  }
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
  }>;
}) {
  const sp = await searchParams;
  const page = Number(sp.page || 1);

  const isFiltered =
    !!sp.q ||
    !!sp.author ||
    (!!sp.category && sp.category !== "all");

  const [{ servers, pagination }, stats, featuredOrgs] = await Promise.all([
    getServers({
      q: sp.q,
      author: sp.author,
      category: sp.category,
      sort: sp.sort,
      order: sp.order,
      page,
    }),
    getStats(),
    getFeaturedServers(),
  ]);

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
          <span className="stats-card-subtitle">MCP servers discovered and analyzed</span>
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

        {/* Card 2 — Green: detection rules */}
        <div className="stats-card stats-card-green">
          <span className="stats-card-big-num">150+</span>
          <span className="stats-card-subtitle">Detection Rules</span>
          <span className="stats-card-green-detail">Deterministic &middot; No LLMs &middot; No false positives</span>
        </div>
      </section>

      {/* ── Featured Official Servers (rotating carousel) ── */}
      {!isFiltered && featuredOrgs.length > 0 && (
        <section className="featured-section" aria-label="Official server integrations">
          <div className="featured-header">
            <h2 className="featured-heading">Official Integrations</h2>
            <a href="/servers" className="featured-view-all">
              Browse all →
            </a>
          </div>
          <FeaturedCarousel orgs={featuredOrgs} />
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
            defaultValue={sp.sort || "name"}
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
        <div className="server-table-wrap" aria-label="MCP server registry">
          <div className="server-table-header">
            <span className="stcol stcol-name">Server</span>
            <span className="stcol stcol-owner">Owner</span>
            <span className="stcol stcol-category">Category</span>
            <span className="stcol stcol-lang">Language</span>
            <span className="stcol stcol-tools">Tools</span>
            <span className="stcol stcol-origin">Source</span>
          </div>
          {servers.map((server) => (
            <a
              key={server.id}
              href={`/server/${server.slug}`}
              className="server-table-row"
            >
              <div className="stcol stcol-name">
                <span className="server-row-name">{server.name}</span>
                {server.description && (
                  <p className="server-row-desc">{server.description}</p>
                )}
              </div>
              <span className="stcol stcol-owner">
                {server.author || "\u2014"}
              </span>
              <span className="stcol stcol-category">
                {server.category ? (
                  <span className="server-meta-chip server-meta-cat">{server.category}</span>
                ) : (
                  <span className="stcol-empty">{"\u2014"}</span>
                )}
              </span>
              <span className="stcol stcol-lang">
                {server.language || "\u2014"}
              </span>
              <span className="stcol stcol-tools">
                {server.tool_count > 0 ? server.tool_count : "\u2014"}
              </span>
              <span className="stcol stcol-origin">
                {server.source_names.length > 0 ? (
                  server.source_names.map((s) => (
                    <span key={s} className="server-meta-chip server-meta-origin">
                      {SOURCE_DISPLAY[s] || s}
                    </span>
                  ))
                ) : (
                  <span className="stcol-empty">{"\u2014"}</span>
                )}
              </span>
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
  if (sp.sort && sp.sort !== "name") params.set("sort", sp.sort);
  if (sp.order && sp.order !== "asc") params.set("order", sp.order);
  if (page > 1) params.set("page", String(page));
  const qs = params.toString();
  return qs ? `/?${qs}` : "/";
}
