import type { Metadata } from "next";
import FeaturedCarousel from "../components/FeaturedCarousel";
import ScannerAnimation from "../components/ScannerAnimation";

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

// ── Official Integrations — 50 curated top-tech MCP servers ─────────────────
// These are the definitive list of servers to feature on the home page.
// Brand colors are verified against each org's official brand guidelines.
// Slugs match the actual server slugs in the database (from crawlers).
// If the server exists in the DB, links go to /servers/:slug. If not, search.

interface FeaturedOrg {
  name: string;
  org: string;
  slug: string;
  desc: string;
  color: string;
  initials: string;
}

const OFFICIAL_INTEGRATIONS: FeaturedOrg[] = [
  // ── Top AI ────────────────────────────────────────────
  { name: "Claude MCP Servers", org: "Anthropic", slug: "mcp-server-filesystem", desc: "Official reference servers: filesystem, GitHub, Postgres, Brave Search, SQLite.", color: "#D4A27F", initials: "AN" },
  { name: "OpenAI Agents SDK", org: "OpenAI", slug: "openai-agents-mcp", desc: "Agent framework with MCP tool integration.", color: "#10A37F", initials: "OA" },
  { name: "Google Gemini MCP", org: "Google", slug: "google-gemini-mcp", desc: "Gemini API, Vertex AI, Google Cloud tools.", color: "#4285F4", initials: "GG" },
  { name: "Cohere MCP Server", org: "Cohere", slug: "cohere-mcp-server", desc: "Cohere LLM APIs, embeddings, reranking.", color: "#39594D", initials: "CO" },
  { name: "Hugging Face MCP", org: "Hugging Face", slug: "huggingface-mcp", desc: "Model hub, inference API, datasets.", color: "#FFD21E", initials: "HF" },
  // ── Developer Platforms ───────────────────────────────
  { name: "GitHub MCP Server", org: "GitHub", slug: "github-mcp-server", desc: "Repositories, issues, pull requests, code search, Actions.", color: "#24292e", initials: "GH" },
  { name: "GitLab MCP Server", org: "GitLab", slug: "gitlab-mcp-server", desc: "Repos, CI/CD pipelines, merge requests.", color: "#FC6D26", initials: "GL" },
  { name: "Vercel MCP Server", org: "Vercel", slug: "vercel-mcp-server", desc: "Deployments, domains, edge functions, analytics.", color: "#000000", initials: "VC" },
  { name: "Netlify MCP Server", org: "Netlify", slug: "netlify-mcp-server", desc: "Sites, deploys, functions, forms.", color: "#00C7B7", initials: "NL" },
  { name: "Render MCP Server", org: "Render", slug: "render-mcp-server", desc: "Services, deploys, databases, cron jobs.", color: "#46E3B7", initials: "RN" },
  // ── Cloud & Infrastructure ────────────────────────────
  { name: "AWS MCP Server", org: "AWS", slug: "aws-mcp-server", desc: "S3, Lambda, DynamoDB, CloudFormation, EC2.", color: "#FF9900", initials: "AW" },
  { name: "Cloudflare MCP Server", org: "Cloudflare", slug: "mcp-server-cloudflare", desc: "Workers, R2, KV, D1, Durable Objects.", color: "#F38020", initials: "CF" },
  { name: "Docker MCP Server", org: "Docker", slug: "docker-mcp-server", desc: "Containers, images, volumes, networks.", color: "#2496ED", initials: "DK" },
  { name: "Kubernetes MCP Server", org: "Kubernetes", slug: "kubernetes-mcp-server", desc: "Pods, deployments, services, config maps.", color: "#326CE5", initials: "K8" },
  { name: "Terraform MCP Server", org: "HashiCorp", slug: "terraform-mcp-server", desc: "Infrastructure as code, state management, plans.", color: "#7B42BC", initials: "TF" },
  // ── Databases ─────────────────────────────────────────
  { name: "Supabase MCP Server", org: "Supabase", slug: "supabase-mcp-server", desc: "Postgres database, auth, storage, edge functions.", color: "#3ECF8E", initials: "SB" },
  { name: "MongoDB MCP Server", org: "MongoDB", slug: "mongodb-mcp-server", desc: "Atlas clusters, collections, aggregation pipelines.", color: "#00ED64", initials: "MG" },
  { name: "Redis MCP Server", org: "Redis", slug: "redis-mcp-server", desc: "Key-value operations, streams, pub/sub.", color: "#FF4438", initials: "RD" },
  { name: "PlanetScale MCP", org: "PlanetScale", slug: "planetscale-mcp-server", desc: "MySQL-compatible serverless databases, branches.", color: "#000000", initials: "PS" },
  { name: "Neon MCP Server", org: "Neon", slug: "neon-mcp-server", desc: "Serverless Postgres, branching, endpoints.", color: "#00E599", initials: "NE" },
  // ── Payments & Fintech ────────────────────────────────
  { name: "Stripe Agent Toolkit", org: "Stripe", slug: "stripe-agent-toolkit", desc: "Payments, customers, invoices, subscriptions.", color: "#635BFF", initials: "ST" },
  { name: "Plaid MCP Server", org: "Plaid", slug: "plaid-mcp-server", desc: "Bank connections, transactions, identity verification.", color: "#000000", initials: "PL" },
  { name: "Square MCP Server", org: "Square", slug: "square-mcp-server", desc: "Payments, catalog, orders, customers.", color: "#006AFF", initials: "SQ" },
  // ── SaaS & Productivity ───────────────────────────────
  { name: "Notion MCP", org: "Notion", slug: "notion-mcp", desc: "Pages, databases, blocks, search.", color: "#000000", initials: "NT" },
  { name: "Slack MCP Server", org: "Slack", slug: "slack-mcp-server", desc: "Channels, messages, users, reactions.", color: "#4A154B", initials: "SL" },
  { name: "Linear MCP", org: "Linear", slug: "linear-mcp", desc: "Issues, projects, cycles, teams.", color: "#5E6AD2", initials: "LN" },
  { name: "Atlassian Remote MCP", org: "Atlassian", slug: "atlassian-remote-mcp-server", desc: "Jira issues, Confluence pages, Bitbucket repos.", color: "#0052CC", initials: "AT" },
  { name: "Asana MCP Server", org: "Asana", slug: "asana-mcp-server", desc: "Tasks, projects, portfolios, goals.", color: "#F06A6A", initials: "AS" },
  { name: "Airtable MCP Server", org: "Airtable", slug: "airtable-mcp-server", desc: "Bases, tables, records, views.", color: "#2D7FF9", initials: "AT" },
  { name: "Monday.com MCP", org: "Monday", slug: "monday-mcp-server", desc: "Boards, items, updates, automations.", color: "#6C6CFF", initials: "MN" },
  // ── Observability & DevOps ────────────────────────────
  { name: "Datadog MCP Server", org: "Datadog", slug: "datadog-mcp-server", desc: "Metrics, logs, traces, monitors, dashboards.", color: "#632CA6", initials: "DD" },
  { name: "Sentry MCP Server", org: "Sentry", slug: "sentry-mcp-server", desc: "Error tracking, performance, releases, alerts.", color: "#362D59", initials: "SN" },
  { name: "Grafana MCP Server", org: "Grafana", slug: "grafana-mcp-server", desc: "Dashboards, alerts, data sources, panels.", color: "#F46800", initials: "GF" },
  { name: "PagerDuty MCP Server", org: "PagerDuty", slug: "pagerduty-mcp-server", desc: "Incidents, services, escalation policies.", color: "#06AC38", initials: "PD" },
  { name: "CircleCI MCP Server", org: "CircleCI", slug: "circleci-mcp-server", desc: "Pipelines, workflows, jobs, orbs.", color: "#343434", initials: "CI" },
  // ── Communication ─────────────────────────────────────
  { name: "Twilio MCP Server", org: "Twilio", slug: "twilio-mcp-server", desc: "SMS, voice, video, authentication.", color: "#F22F46", initials: "TW" },
  { name: "SendGrid MCP Server", org: "SendGrid", slug: "sendgrid-mcp-server", desc: "Email delivery, templates, analytics.", color: "#1A82E2", initials: "SG" },
  // ── Security & Auth ───────────────────────────────────
  { name: "1Password MCP", org: "1Password", slug: "1password-mcp-server", desc: "Vaults, items, secrets management.", color: "#0572EC", initials: "1P" },
  { name: "Okta MCP Server", org: "Okta", slug: "okta-mcp-server", desc: "Users, groups, apps, auth policies.", color: "#007DC1", initials: "OK" },
  { name: "Auth0 MCP Server", org: "Auth0", slug: "auth0-mcp-server", desc: "Tenants, users, rules, connections.", color: "#EB5424", initials: "A0" },
  // ── Design & CRM ──────────────────────────────────────
  { name: "Figma MCP Server", org: "Figma", slug: "figma-mcp-server", desc: "Design files, components, variables, styles.", color: "#A259FF", initials: "FG" },
  { name: "Salesforce MCP", org: "Salesforce", slug: "salesforce-mcp-server", desc: "CRM objects, SOQL queries, workflows.", color: "#00A1E0", initials: "SF" },
  { name: "HubSpot MCP Server", org: "HubSpot", slug: "hubspot-mcp-server", desc: "Contacts, deals, tickets, marketing.", color: "#FF7A59", initials: "HS" },
  { name: "Shopify MCP Server", org: "Shopify", slug: "shopify-mcp-server", desc: "Products, orders, customers, inventory.", color: "#95BF47", initials: "SH" },
  // ── Data & Analytics ──────────────────────────────────
  { name: "Snowflake MCP Server", org: "Snowflake", slug: "snowflake-mcp-server", desc: "Warehouses, queries, stages, pipes.", color: "#29B5E8", initials: "SW" },
  { name: "Databricks MCP", org: "Databricks", slug: "databricks-mcp-server", desc: "Notebooks, jobs, clusters, Unity Catalog.", color: "#FF3621", initials: "DB" },
  // ── Developer Tools ───────────────────────────────────
  { name: "Postman MCP Server", org: "Postman", slug: "postman-mcp-server", desc: "Collections, environments, monitors, APIs.", color: "#FF6C37", initials: "PM" },
  { name: "Prisma MCP Server", org: "Prisma", slug: "prisma-mcp-server", desc: "Schema management, migrations, queries.", color: "#2D3748", initials: "PR" },
  { name: "LaunchDarkly MCP", org: "LaunchDarkly", slug: "launchdarkly-mcp-server", desc: "Feature flags, segments, experiments.", color: "#405BFF", initials: "LD" },
  { name: "Brave Search MCP", org: "Brave", slug: "brave-search-mcp", desc: "Web search, news, images via Brave API.", color: "#FB542B", initials: "BR" },
];

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

  const [{ servers, pagination }, stats] = await Promise.all([
    getServers({
      q: sp.q,
      author: sp.author,
      category: sp.category,
      sort: sp.sort,
      order: sp.order,
      page,
    }),
    getStats(),
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
          <span className="stats-card-big-num">177</span>
          <span className="stats-card-subtitle">Detection Rules</span>
          <span className="stats-card-green-detail">Deterministic &middot; No LLMs &middot; No false positives</span>
        </div>

        {/* Card 3 — Scanner animation */}
        <ScannerAnimation />
      </section>

      {/* ── Featured Official Servers (rotating carousel) ── */}
      {!isFiltered && (
        <section className="featured-section" aria-label="Official server integrations">
          <div className="featured-header">
            <h2 className="featured-heading">Official Integrations</h2>
            <a href="/servers" className="featured-view-all">
              Browse all →
            </a>
          </div>
          <FeaturedCarousel orgs={OFFICIAL_INTEGRATIONS} />
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
