const API_URL = process.env.API_URL || "http://localhost:3100";

interface Server {
  id: string;
  name: string;
  slug: string;
  description: string | null;
  author: string | null;
  category: string | null;
  latest_score: number | null;
  github_stars: number | null;
}

async function getServers(query?: string): Promise<{ servers: Server[]; total: number }> {
  try {
    const params = new URLSearchParams({ limit: "50", sort: "score", order: "desc" });
    if (query) params.set("q", query);

    const res = await fetch(`${API_URL}/api/v1/servers?${params}`, {
      next: { revalidate: 300 },
    });
    if (!res.ok) return { servers: [], total: 0 };
    const data = await res.json();
    return { servers: data.data || [], total: data.pagination?.total || 0 };
  } catch {
    return { servers: [], total: 0 };
  }
}

async function getStats() {
  try {
    const res = await fetch(`${API_URL}/api/v1/ecosystem/stats`, {
      next: { revalidate: 300 },
    });
    if (!res.ok) return null;
    const data = await res.json();
    return data.data;
  } catch {
    return null;
  }
}

function ScoreBadge({ score }: { score: number | null }) {
  if (score === null) {
    return (
      <span style={{ color: "#666", fontSize: "14px" }}>Unscanned</span>
    );
  }

  let color = "#e05d44";
  if (score >= 80) color = "#4c1";
  else if (score >= 60) color = "#dfb317";
  else if (score >= 40) color = "#fe7d37";

  return (
    <span
      style={{
        backgroundColor: color,
        color: "#fff",
        padding: "2px 8px",
        borderRadius: "4px",
        fontSize: "14px",
        fontWeight: 700,
      }}
    >
      {score}
    </span>
  );
}

export default async function HomePage() {
  const [{ servers, total }, stats] = await Promise.all([
    getServers(),
    getStats(),
  ]);

  return (
    <div>
      {/* Hero */}
      <section style={{ textAlign: "center", padding: "48px 0 32px" }}>
        <h1 style={{ fontSize: "36px", margin: "0 0 12px" }}>
          MCP Server Security Registry
        </h1>
        <p style={{ color: "#888", fontSize: "18px", maxWidth: "600px", margin: "0 auto" }}>
          Search {stats?.total_servers?.toLocaleString() || "thousands of"} MCP
          servers. Compare security scores. Make informed decisions.
        </p>
      </section>

      {/* Stats */}
      {stats && (
        <section
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(4, 1fr)",
            gap: "16px",
            marginBottom: "32px",
          }}
        >
          <StatCard label="Total Servers" value={stats.total_servers?.toLocaleString() || "0"} />
          <StatCard label="Scanned" value={stats.total_scanned?.toLocaleString() || "0"} />
          <StatCard label="Average Score" value={`${stats.average_score || 0}/100`} />
          <StatCard
            label="Categories"
            value={Object.keys(stats.category_breakdown || {}).length.toString()}
          />
        </section>
      )}

      {/* Search */}
      <section style={{ marginBottom: "24px" }}>
        <form action="/" method="GET">
          <input
            type="search"
            name="q"
            placeholder="Search MCP servers by name, author, or category..."
            style={{
              width: "100%",
              padding: "12px 16px",
              fontSize: "16px",
              backgroundColor: "#1a1a1a",
              border: "1px solid #333",
              borderRadius: "8px",
              color: "#ededed",
              boxSizing: "border-box",
            }}
          />
        </form>
      </section>

      {/* Server List */}
      <section>
        <h2 style={{ fontSize: "18px", marginBottom: "16px" }}>
          Top Servers by Security Score ({total} total)
        </h2>
        <table
          style={{
            width: "100%",
            borderCollapse: "collapse",
          }}
        >
          <thead>
            <tr style={{ borderBottom: "1px solid #333", textAlign: "left" }}>
              <th style={{ padding: "8px", color: "#888" }}>Server</th>
              <th style={{ padding: "8px", color: "#888" }}>Category</th>
              <th style={{ padding: "8px", color: "#888" }}>Author</th>
              <th style={{ padding: "8px", color: "#888", textAlign: "right" }}>Stars</th>
              <th style={{ padding: "8px", color: "#888", textAlign: "right" }}>Score</th>
            </tr>
          </thead>
          <tbody>
            {servers.map((server) => (
              <tr
                key={server.id}
                style={{ borderBottom: "1px solid #1a1a1a" }}
              >
                <td style={{ padding: "12px 8px" }}>
                  <a
                    href={`/server/${server.slug}`}
                    style={{ color: "#58a6ff", textDecoration: "none" }}
                  >
                    {server.name}
                  </a>
                  {server.description && (
                    <p
                      style={{
                        color: "#666",
                        fontSize: "13px",
                        margin: "4px 0 0",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                        maxWidth: "400px",
                      }}
                    >
                      {server.description}
                    </p>
                  )}
                </td>
                <td style={{ padding: "12px 8px", color: "#888", fontSize: "13px" }}>
                  {server.category || "—"}
                </td>
                <td style={{ padding: "12px 8px", color: "#888", fontSize: "13px" }}>
                  {server.author || "—"}
                </td>
                <td style={{ padding: "12px 8px", textAlign: "right", color: "#888", fontSize: "13px" }}>
                  {server.github_stars?.toLocaleString() || "—"}
                </td>
                <td style={{ padding: "12px 8px", textAlign: "right" }}>
                  <ScoreBadge score={server.latest_score} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}

function StatCard({ label, value }: { label: string; value: string }) {
  return (
    <div
      style={{
        backgroundColor: "#1a1a1a",
        border: "1px solid #333",
        borderRadius: "8px",
        padding: "16px",
        textAlign: "center",
      }}
    >
      <div style={{ fontSize: "24px", fontWeight: 700 }}>{value}</div>
      <div style={{ color: "#888", fontSize: "13px", marginTop: "4px" }}>
        {label}
      </div>
    </div>
  );
}
