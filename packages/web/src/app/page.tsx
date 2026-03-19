import type { Metadata } from "next";
import FeaturedCarousel from "../components/FeaturedCarousel";

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
  { value: "score", label: "Score" },
  { value: "stars", label: "Stars" },
  { value: "downloads", label: "Downloads" },
  { value: "name", label: "Name" },
  { value: "updated", label: "Last Updated" },
];

// ── Official org featured servers (50 top tech orgs) ────────────────────────
interface FeaturedOrg {
  name: string;
  org: string;
  slug: string;
  desc: string;
  color: string;
  initials: string;
}

const FEATURED_ORGS: FeaturedOrg[] = [
  { name: "GitHub MCP Server", org: "GitHub", slug: "github-mcp-server", desc: "Repos, issues, PRs, code search, Actions.", color: "#0969da", initials: "GH" },
  { name: "Stripe Agent Toolkit", org: "Stripe", slug: "stripe-agent-toolkit", desc: "Payments, customers, invoices, subscriptions.", color: "#635BFF", initials: "ST" },
  { name: "Cloudflare MCP Server", org: "Cloudflare", slug: "mcp-server-cloudflare", desc: "Workers, R2, KV, D1, Durable Objects.", color: "#F6821F", initials: "CF" },
  { name: "Linear MCP", org: "Linear", slug: "linear-mcp", desc: "Issues, projects, cycles, teams.", color: "#5E6AD2", initials: "LN" },
  { name: "Notion MCP", org: "Notion", slug: "notion-mcp", desc: "Pages, databases, blocks, search.", color: "#000000", initials: "NT" },
  { name: "Atlassian Remote MCP", org: "Atlassian", slug: "atlassian-remote-mcp-server", desc: "Jira issues, Confluence pages, Bitbucket.", color: "#0052CC", initials: "AT" },
  { name: "Slack MCP Server", org: "Slack", slug: "slack-mcp-server", desc: "Channels, messages, users, reactions.", color: "#4A154B", initials: "SL" },
  { name: "Google Drive MCP", org: "Google", slug: "google-drive-mcp", desc: "Drive files, Docs, Sheets, permissions.", color: "#4285F4", initials: "GG" },
  { name: "Microsoft Graph MCP", org: "Microsoft", slug: "microsoft-graph-mcp", desc: "Office 365, Teams, OneDrive, Outlook.", color: "#00A4EF", initials: "MS" },
  { name: "AWS MCP Server", org: "AWS", slug: "aws-mcp-server", desc: "S3, Lambda, DynamoDB, CloudFormation.", color: "#FF9900", initials: "AW" },
  { name: "Vercel MCP Server", org: "Vercel", slug: "vercel-mcp-server", desc: "Deployments, domains, edge functions.", color: "#000000", initials: "VC" },
  { name: "Supabase MCP Server", org: "Supabase", slug: "supabase-mcp-server", desc: "Database, auth, storage, edge functions.", color: "#3ECF8E", initials: "SB" },
  { name: "Datadog MCP Server", org: "Datadog", slug: "datadog-mcp-server", desc: "Metrics, logs, traces, monitors.", color: "#632CA6", initials: "DD" },
  { name: "PagerDuty MCP Server", org: "PagerDuty", slug: "pagerduty-mcp-server", desc: "Incidents, services, escalation policies.", color: "#06AC38", initials: "PD" },
  { name: "Sentry MCP Server", org: "Sentry", slug: "sentry-mcp-server", desc: "Errors, performance, releases, alerts.", color: "#362D59", initials: "SN" },
  { name: "MongoDB MCP Server", org: "MongoDB", slug: "mongodb-mcp-server", desc: "Atlas clusters, collections, aggregation.", color: "#00ED64", initials: "MG" },
  { name: "Redis MCP Server", org: "Redis", slug: "redis-mcp-server", desc: "Key-value ops, streams, pub/sub.", color: "#DC382D", initials: "RD" },
  { name: "Twilio MCP Server", org: "Twilio", slug: "twilio-mcp-server", desc: "SMS, voice, video, authentication.", color: "#F22F46", initials: "TW" },
  { name: "SendGrid MCP Server", org: "SendGrid", slug: "sendgrid-mcp-server", desc: "Email delivery, templates, analytics.", color: "#1A82E2", initials: "SG" },
  { name: "Figma MCP Server", org: "Figma", slug: "figma-mcp-server", desc: "Design files, components, variables.", color: "#F24E1E", initials: "FG" },
  { name: "Shopify MCP Server", org: "Shopify", slug: "shopify-mcp-server", desc: "Products, orders, customers, inventory.", color: "#96BF48", initials: "SH" },
  { name: "Salesforce MCP Server", org: "Salesforce", slug: "salesforce-mcp-server", desc: "CRM objects, SOQL queries, workflows.", color: "#00A1E0", initials: "SF" },
  { name: "HubSpot MCP Server", org: "HubSpot", slug: "hubspot-mcp-server", desc: "Contacts, deals, tickets, marketing.", color: "#FF7A59", initials: "HS" },
  { name: "Zendesk MCP Server", org: "Zendesk", slug: "zendesk-mcp-server", desc: "Tickets, users, organizations, search.", color: "#03363D", initials: "ZD" },
  { name: "Jira MCP Server", org: "Jira", slug: "jira-mcp-server", desc: "Issues, sprints, boards, epics.", color: "#0052CC", initials: "JR" },
  { name: "Confluence MCP Server", org: "Confluence", slug: "confluence-mcp-server", desc: "Pages, spaces, comments, search.", color: "#172B4D", initials: "CN" },
  { name: "GitLab MCP Server", org: "GitLab", slug: "gitlab-mcp-server", desc: "Repos, CI/CD pipelines, merge requests.", color: "#FC6D26", initials: "GL" },
  { name: "Bitbucket MCP Server", org: "Bitbucket", slug: "bitbucket-mcp-server", desc: "Repos, pull requests, pipelines.", color: "#0052CC", initials: "BB" },
  { name: "Docker MCP Server", org: "Docker", slug: "docker-mcp-server", desc: "Containers, images, volumes, networks.", color: "#2496ED", initials: "DK" },
  { name: "Kubernetes MCP Server", org: "Kubernetes", slug: "kubernetes-mcp-server", desc: "Pods, deployments, services, config.", color: "#326CE5", initials: "K8" },
  { name: "Terraform MCP Server", org: "HashiCorp", slug: "terraform-mcp-server", desc: "Infrastructure as code, state, plans.", color: "#7B42BC", initials: "TF" },
  { name: "Snowflake MCP Server", org: "Snowflake", slug: "snowflake-mcp-server", desc: "Warehouses, queries, stages, pipes.", color: "#29B5E8", initials: "SF" },
  { name: "Databricks MCP Server", org: "Databricks", slug: "databricks-mcp-server", desc: "Notebooks, jobs, clusters, Unity Catalog.", color: "#FF3621", initials: "DB" },
  { name: "Elastic MCP Server", org: "Elastic", slug: "elastic-mcp-server", desc: "Search, observability, security analytics.", color: "#FEC514", initials: "EL" },
  { name: "Grafana MCP Server", org: "Grafana", slug: "grafana-mcp-server", desc: "Dashboards, alerts, data sources.", color: "#F46800", initials: "GF" },
  { name: "New Relic MCP Server", org: "New Relic", slug: "new-relic-mcp-server", desc: "APM, infrastructure, logs, NRQL.", color: "#008C99", initials: "NR" },
  { name: "Splunk MCP Server", org: "Splunk", slug: "splunk-mcp-server", desc: "Search, dashboards, alerts, SPL queries.", color: "#65A637", initials: "SP" },
  { name: "Airtable MCP Server", org: "Airtable", slug: "airtable-mcp-server", desc: "Bases, tables, records, views.", color: "#18BFFF", initials: "AT" },
  { name: "Asana MCP Server", org: "Asana", slug: "asana-mcp-server", desc: "Tasks, projects, portfolios, goals.", color: "#F06A6A", initials: "AS" },
  { name: "Monday.com MCP Server", org: "Monday", slug: "monday-mcp-server", desc: "Boards, items, updates, automations.", color: "#FF3D57", initials: "MN" },
  { name: "Okta MCP Server", org: "Okta", slug: "okta-mcp-server", desc: "Users, groups, apps, auth policies.", color: "#007DC1", initials: "OK" },
  { name: "Auth0 MCP Server", org: "Auth0", slug: "auth0-mcp-server", desc: "Tenants, users, rules, connections.", color: "#EB5424", initials: "A0" },
  { name: "Postman MCP Server", org: "Postman", slug: "postman-mcp-server", desc: "Collections, environments, monitors.", color: "#FF6C37", initials: "PM" },
  { name: "CircleCI MCP Server", org: "CircleCI", slug: "circleci-mcp-server", desc: "Pipelines, workflows, jobs, orbs.", color: "#343434", initials: "CI" },
  { name: "LaunchDarkly MCP Server", org: "LaunchDarkly", slug: "launchdarkly-mcp-server", desc: "Feature flags, segments, experiments.", color: "#405BFF", initials: "LD" },
  { name: "Prisma MCP Server", org: "Prisma", slug: "prisma-mcp-server", desc: "Schema management, migrations, queries.", color: "#2D3748", initials: "PR" },
  { name: "Planetscale MCP Server", org: "PlanetScale", slug: "planetscale-mcp-server", desc: "Databases, branches, deploy requests.", color: "#000000", initials: "PS" },
  { name: "Neon MCP Server", org: "Neon", slug: "neon-mcp-server", desc: "Serverless Postgres, branches, endpoints.", color: "#00E599", initials: "NE" },
  { name: "Render MCP Server", org: "Render", slug: "render-mcp-server", desc: "Services, deploys, databases, cron jobs.", color: "#46E3B7", initials: "RN" },
  { name: "Fly.io MCP Server", org: "Fly.io", slug: "fly-mcp-server", desc: "Apps, machines, volumes, secrets.", color: "#7B3FE4", initials: "FY" },
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

      {/* ── Featured Official Servers (rotating carousel) ── */}
      {!isFiltered && (
        <section className="featured-section" aria-label="Official server integrations">
          <div className="featured-header">
            <h2 className="featured-heading">Official Integrations</h2>
            <a href="/?sort=score&order=desc" className="featured-view-all">
              Browse all →
            </a>
          </div>
          <FeaturedCarousel orgs={FEATURED_ORGS} />
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
        <div className="server-table-wrap" aria-label="MCP server registry">
          <div className="server-table-header">
            <span className="stcol stcol-name">Server</span>
            <span className="stcol stcol-owner">Owner</span>
            <span className="stcol stcol-category">Category</span>
            <span className="stcol stcol-lang">Language</span>
            <span className="stcol stcol-tools">Tools</span>
            <span className="stcol stcol-origin">Source</span>
            <span className="stcol stcol-score">Score</span>
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
              <span className="stcol stcol-score">
                <ScoreBadge score={server.latest_score} />
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
  if (sp.sort && sp.sort !== "score") params.set("sort", sp.sort);
  if (sp.order && sp.order !== "desc") params.set("order", sp.order);
  if (sp.min_score) params.set("min_score", sp.min_score);
  if (page > 1) params.set("page", String(page));
  const qs = params.toString();
  return qs ? `/?${qs}` : "/";
}
