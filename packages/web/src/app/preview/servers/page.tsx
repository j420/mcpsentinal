/**
 * Preview /servers — canonical list with the score column the live /servers
 * page omits.
 *
 * Honest-data policy: every visible field is read from the API. A server with
 * no score yet displays "Awaiting scan" rather than a fabricated number.
 * A server with a score but no confidence band shows the score without the
 * band rather than inventing one.
 *
 * Reads from `/api/v1/servers`. If the API does not yet include
 * `latest_score` / `confidence_band` on the list response, the row gracefully
 * falls through to "Awaiting scan" — this page never invents data.
 */

import type { Metadata } from "next";

export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Servers",
  description:
    "Search every MCP server in the registry, score visible at the row level. Preview information architecture.",
};

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3100";

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
  tool_count: number;
  connection_status: "success" | "failed" | "timeout" | "no_endpoint" | null;
  github_url: string | null;
  npm_package: string | null;
  pypi_package: string | null;
  /* Optional score fields — gracefully absent if the API hasn't shipped them yet. */
  latest_score?: number | null;
  confidence_band?: "high" | "medium" | "low" | "minimal" | null;
  findings_count?: number | null;
  last_scanned_at?: string | null;
}

interface Pagination {
  total: number;
  page: number;
  limit: number;
  pages: number;
}

async function getServers(params: {
  q?: string;
  category?: string;
  sort?: string;
  order?: string;
  page?: number;
}): Promise<{ servers: Server[]; pagination: Pagination; apiUp: boolean }> {
  try {
    const sp = new URLSearchParams();
    sp.set("limit", "25");
    sp.set("sort", params.sort || "name");
    sp.set("order", params.order || "asc");
    if (params.q) sp.set("q", params.q);
    if (params.category && params.category !== "all")
      sp.set("category", params.category);
    if (params.page && params.page > 1) sp.set("page", String(params.page));

    const res = await fetch(`${API_URL}/api/v1/servers?${sp}`, {
      signal: AbortSignal.timeout(4000),
    });
    if (!res.ok) {
      return {
        servers: [],
        pagination: { total: 0, page: 1, limit: 25, pages: 0 },
        apiUp: false,
      };
    }
    const data = await res.json();
    return {
      servers: data.data || [],
      pagination:
        data.pagination || { total: 0, page: 1, limit: 25, pages: 0 },
      apiUp: true,
    };
  } catch {
    return {
      servers: [],
      pagination: { total: 0, page: 1, limit: 25, pages: 0 },
      apiUp: false,
    };
  }
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
  { value: "name", label: "Name" },
  { value: "stars", label: "Stars" },
  { value: "downloads", label: "Downloads" },
  { value: "updated", label: "Last Updated" },
];

function scoreColor(score: number): string {
  if (score >= 80) return "var(--good)";
  if (score >= 60) return "var(--moderate)";
  if (score >= 40) return "var(--poor)";
  return "var(--critical)";
}

function scoreLabel(score: number): string {
  if (score >= 80) return "Good";
  if (score >= 60) return "Moderate";
  if (score >= 40) return "Poor";
  return "Critical";
}

function bandTooltip(band: string | null | undefined): string {
  switch (band) {
    case "high":
      return "High confidence — source code analysed, live connection observed, 80%+ rules applied";
    case "medium":
      return "Medium confidence — partial coverage, 60–80% rules applied";
    case "low":
      return "Low confidence — limited data, 30–60% rules applied";
    case "minimal":
      return "Minimal coverage — fewer than 30% of rules applicable to this scan";
    default:
      return "Confidence band not available for this scan";
  }
}

function buildPageUrl(
  sp: Record<string, string | undefined>,
  page: number
): string {
  const params = new URLSearchParams();
  if (sp.q) params.set("q", sp.q);
  if (sp.category && sp.category !== "all")
    params.set("category", sp.category);
  if (sp.sort && sp.sort !== "name") params.set("sort", sp.sort);
  if (sp.order && sp.order !== "asc") params.set("order", sp.order);
  if (page > 1) params.set("page", String(page));
  const qs = params.toString();
  return qs ? `/preview/servers?${qs}` : "/preview/servers";
}

export default async function PreviewServersPage({
  searchParams,
}: {
  searchParams: Promise<{
    q?: string;
    category?: string;
    sort?: string;
    order?: string;
    page?: string;
  }>;
}) {
  const sp = await searchParams;
  const page = Number(sp.page || 1);

  const { servers, pagination, apiUp } = await getServers({
    q: sp.q,
    category: sp.category,
    sort: sp.sort,
    order: sp.order,
    page,
  });

  const haveAnyScore = servers.some(
    (s) => typeof s.latest_score === "number"
  );

  return (
    <>
      {/* ── Header ──────────────────────────────────── */}
      <section
        style={{
          padding: "var(--s8) 0 var(--s5)",
          borderBottom: "1px solid var(--border)",
        }}
      >
        <p
          style={{
            fontFamily: "var(--font-mono)",
            fontSize: "11px",
            letterSpacing: "0.06em",
            textTransform: "uppercase",
            color: "var(--text-3)",
            marginBottom: "var(--s2)",
          }}
        >
          Servers · Canonical list
        </p>
        <h1
          style={{
            fontFamily: "var(--font-body)",
            fontSize: "clamp(28px, 4vw, 40px)",
            fontWeight: 700,
            letterSpacing: "-0.03em",
            color: "var(--text)",
            marginBottom: "var(--s3)",
          }}
        >
          {pagination.total > 0
            ? `${pagination.total.toLocaleString()} servers`
            : "Servers"}
        </h1>
        <p
          style={{
            fontSize: "15px",
            color: "var(--text-2)",
            lineHeight: 1.6,
            maxWidth: "640px",
          }}
        >
          Score and confidence band shown at the row level when the API has
          scored the server. Servers awaiting scan say so explicitly — never
          confused with a clean result.
        </p>

        {!apiUp && (
          <div
            role="alert"
            style={{
              marginTop: "var(--s4)",
              padding: "var(--s3) var(--s4)",
              background: "var(--surface-2)",
              border: "1px solid var(--border)",
              borderRadius: "6px",
              fontSize: "13px",
              color: "var(--text-2)",
            }}
          >
            API unreachable. Showing nothing rather than stale or invented
            data.
          </div>
        )}
      </section>

      {/* ── Filters ─────────────────────────────────── */}
      <form
        method="GET"
        action="/preview/servers"
        style={{
          padding: "var(--s5) 0",
          borderBottom: "1px solid var(--border)",
        }}
      >
        <div
          style={{
            display: "flex",
            gap: "var(--s3)",
            alignItems: "center",
            flexWrap: "wrap",
          }}
        >
          <input
            className="search-input"
            type="search"
            name="q"
            defaultValue={sp.q || ""}
            placeholder="Search by name, author, or description…"
            autoComplete="off"
            style={{ flex: "1 1 280px", minWidth: "260px" }}
          />
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
            name="sort"
            defaultValue={sp.sort || "name"}
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
            defaultValue={sp.order || "asc"}
          >
            <option value="asc">Ascending</option>
            <option value="desc">Descending</option>
          </select>
          <button type="submit" className="btn-primary btn-primary-sm">
            Apply
          </button>
        </div>
      </form>

      {/* ── Disclosure when no scores yet ───────────── */}
      {servers.length > 0 && !haveAnyScore && (
        <div
          style={{
            margin: "var(--s5) 0 0",
            padding: "var(--s3) var(--s4)",
            fontFamily: "var(--font-mono)",
            fontSize: "12px",
            color: "var(--text-3)",
            background: "var(--surface-2)",
            border: "1px solid var(--border)",
            borderRadius: "6px",
          }}
        >
          The API on this page is not yet returning <code>latest_score</code>{" "}
          on list responses. Each row links to the server detail where the
          score is available. Adding the score to the list response is a
          separate API change tracked in Bucket 1.
        </div>
      )}

      {/* ── Server rows ─────────────────────────────── */}
      {servers.length === 0 ? (
        <div
          style={{
            padding: "var(--s10) var(--s4)",
            textAlign: "center",
            color: "var(--text-2)",
          }}
        >
          <h3 style={{ fontSize: "18px", marginBottom: "var(--s2)" }}>
            No servers match
          </h3>
          <p style={{ fontSize: "14px" }}>
            Try a different search or remove a filter.
          </p>
        </div>
      ) : (
        <div
          role="table"
          aria-label="Server registry"
          style={{ marginTop: "var(--s5)" }}
        >
          {/* Header row */}
          <div
            role="row"
            style={{
              display: "grid",
              gridTemplateColumns:
                "minmax(0, 2.4fr) minmax(0, 1fr) minmax(0, 0.8fr) minmax(0, 0.8fr) minmax(0, 1.2fr)",
              gap: "var(--s3)",
              padding: "var(--s3) var(--s4)",
              fontFamily: "var(--font-mono)",
              fontSize: "11px",
              letterSpacing: "0.06em",
              textTransform: "uppercase",
              color: "var(--text-3)",
              borderBottom: "1px solid var(--border)",
            }}
          >
            <span>Server</span>
            <span>Author</span>
            <span>Category</span>
            <span>Tools</span>
            <span style={{ textAlign: "right" }}>Score</span>
          </div>

          {servers.map((server) => (
            <a
              key={server.id}
              href={`/servers/${server.slug}`}
              role="row"
              style={{
                display: "grid",
                gridTemplateColumns:
                  "minmax(0, 2.4fr) minmax(0, 1fr) minmax(0, 0.8fr) minmax(0, 0.8fr) minmax(0, 1.2fr)",
                gap: "var(--s3)",
                padding: "var(--s4)",
                borderBottom: "1px solid var(--border)",
                color: "var(--text)",
                textDecoration: "none",
                transition: "background 100ms ease",
              }}
            >
              <div role="cell" style={{ minWidth: 0 }}>
                <p
                  style={{
                    fontWeight: 600,
                    fontSize: "15px",
                    color: "var(--text)",
                    marginBottom: "4px",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {server.name}
                </p>
                {server.description && (
                  <p
                    style={{
                      fontSize: "13px",
                      color: "var(--text-2)",
                      lineHeight: 1.5,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      display: "-webkit-box",
                      WebkitLineClamp: 2,
                      WebkitBoxOrient: "vertical",
                    }}
                  >
                    {server.description}
                  </p>
                )}
              </div>

              <div
                role="cell"
                style={{
                  fontSize: "13px",
                  color: "var(--text-2)",
                  alignSelf: "center",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                }}
              >
                {server.author ?? "—"}
              </div>

              <div
                role="cell"
                style={{
                  fontSize: "12px",
                  color: "var(--text-2)",
                  alignSelf: "center",
                }}
              >
                {server.category ?? "—"}
              </div>

              <div
                role="cell"
                style={{
                  fontFamily: "var(--font-mono)",
                  fontSize: "13px",
                  color: "var(--text-2)",
                  alignSelf: "center",
                }}
              >
                {server.tool_count > 0 ? server.tool_count : "—"}
              </div>

              <div
                role="cell"
                style={{
                  alignSelf: "center",
                  textAlign: "right",
                }}
              >
                <ScoreCell server={server} />
              </div>
            </a>
          ))}
        </div>
      )}

      {/* ── Pagination ──────────────────────────────── */}
      {pagination.pages > 1 && (
        <nav
          aria-label="Page navigation"
          style={{
            display: "flex",
            gap: "4px",
            alignItems: "center",
            justifyContent: "center",
            marginTop: "var(--s8)",
          }}
        >
          {page > 1 && (
            <a
              href={buildPageUrl(sp, page - 1)}
              className="page-btn"
              aria-label="Previous page"
            >
              ←
            </a>
          )}
          {Array.from(
            { length: Math.min(pagination.pages, 7) },
            (_, i) => i + 1
          ).map((p) => (
            <a
              key={p}
              href={buildPageUrl(sp, p)}
              className={`page-btn${p === page ? " active" : ""}`}
              aria-current={p === page ? "page" : undefined}
            >
              {p}
            </a>
          ))}
          {pagination.pages > 7 && page < pagination.pages && (
            <>
              <span className="pagination-ellipsis">…</span>
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

function ScoreCell({ server }: { server: Server }) {
  const score = server.latest_score;

  if (typeof score !== "number") {
    return (
      <span
        title="This server has not been scanned yet, or the API has not yet shipped score on the list response."
        style={{
          fontFamily: "var(--font-mono)",
          fontSize: "12px",
          color: "var(--text-3)",
          letterSpacing: "0.02em",
        }}
      >
        Awaiting scan
      </span>
    );
  }

  const color = scoreColor(score);
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "baseline",
        gap: "8px",
      }}
    >
      <span
        style={{
          fontFamily: "var(--font-mono)",
          fontSize: "18px",
          fontWeight: 600,
          color,
          letterSpacing: "-0.01em",
        }}
        aria-label={`Score ${score} out of 100, ${scoreLabel(score)}`}
      >
        {score}
      </span>
      {server.confidence_band && (
        <span
          title={bandTooltip(server.confidence_band)}
          style={{
            fontFamily: "var(--font-mono)",
            fontSize: "10px",
            color: "var(--text-3)",
            textTransform: "uppercase",
            letterSpacing: "0.04em",
          }}
        >
          {server.confidence_band}
        </span>
      )}
    </span>
  );
}
