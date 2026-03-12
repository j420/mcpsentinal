import type { Metadata } from "next";

const API_URL = process.env.API_URL || "http://localhost:3100";

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
  github_stars: number | null;
  npm_downloads: number | null;
  latest_score: number | null;
  last_commit: string | null;
  tools: Array<{
    name: string;
    description: string | null;
    capability_tags: string[];
  }>;
  findings: Array<{
    rule_id: string;
    severity: string;
    evidence: string;
    remediation: string;
    owasp_category: string | null;
  }>;
}

async function getServer(slug: string): Promise<ServerDetail | null> {
  try {
    const res = await fetch(`${API_URL}/api/v1/servers/${slug}`, {
      next: { revalidate: 300 },
    });
    if (!res.ok) return null;
    const data = await res.json();
    return data.data;
  } catch {
    return null;
  }
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ slug: string }>;
}): Promise<Metadata> {
  const { slug } = await params;
  const server = await getServer(slug);
  if (!server) return { title: "Server Not Found — MCP Sentinel" };

  return {
    title: `${server.name} Security Score — MCP Sentinel`,
    description: `Security analysis of ${server.name} MCP server. Score: ${server.latest_score ?? "Unscanned"}/100. ${server.findings?.length || 0} findings detected.`,
  };
}

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: "#e05d44",
    high: "#fe7d37",
    medium: "#dfb317",
    low: "#4c1",
    informational: "#888",
  };

  return (
    <span
      style={{
        backgroundColor: colors[severity] || "#888",
        color: "#fff",
        padding: "2px 6px",
        borderRadius: "3px",
        fontSize: "12px",
        fontWeight: 600,
        textTransform: "uppercase",
      }}
    >
      {severity}
    </span>
  );
}

export default async function ServerPage({
  params,
}: {
  params: Promise<{ slug: string }>;
}) {
  const { slug } = await params;
  const server = await getServer(slug);

  if (!server) {
    return <h1>Server not found</h1>;
  }

  const score = server.latest_score;
  let scoreColor = "#888";
  let scoreLabel = "Unscanned";
  if (score !== null) {
    scoreLabel = `${score}/100`;
    if (score >= 80) scoreColor = "#4c1";
    else if (score >= 60) scoreColor = "#dfb317";
    else if (score >= 40) scoreColor = "#fe7d37";
    else scoreColor = "#e05d44";
  }

  return (
    <div>
      {/* Header */}
      <section
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "flex-start",
          marginBottom: "32px",
        }}
      >
        <div>
          <h1 style={{ margin: "0 0 8px", fontSize: "28px" }}>{server.name}</h1>
          {server.description && (
            <p style={{ color: "#888", margin: "0 0 12px", maxWidth: "600px" }}>
              {server.description}
            </p>
          )}
          <div style={{ display: "flex", gap: "16px", fontSize: "14px", color: "#888" }}>
            {server.author && <span>By {server.author}</span>}
            {server.category && <span>{server.category}</span>}
            {server.language && <span>{server.language}</span>}
            {server.license && <span>{server.license}</span>}
          </div>
          <div style={{ display: "flex", gap: "16px", marginTop: "8px", fontSize: "14px" }}>
            {server.github_url && (
              <a href={server.github_url} style={{ color: "#58a6ff" }}>
                GitHub
              </a>
            )}
            {server.npm_package && (
              <a
                href={`https://www.npmjs.com/package/${server.npm_package}`}
                style={{ color: "#58a6ff" }}
              >
                npm
              </a>
            )}
          </div>
        </div>
        <div
          style={{
            textAlign: "center",
            padding: "16px 24px",
            backgroundColor: "#1a1a1a",
            borderRadius: "8px",
            border: `2px solid ${scoreColor}`,
          }}
        >
          <div style={{ fontSize: "36px", fontWeight: 700, color: scoreColor }}>
            {score ?? "—"}
          </div>
          <div style={{ color: "#888", fontSize: "13px" }}>Security Score</div>
        </div>
      </section>

      {/* Quick Stats */}
      <section
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(4, 1fr)",
          gap: "12px",
          marginBottom: "32px",
        }}
      >
        <MiniStat label="Tools" value={server.tools?.length.toString() || "0"} />
        <MiniStat label="Findings" value={server.findings?.length.toString() || "0"} />
        <MiniStat label="Stars" value={server.github_stars?.toLocaleString() || "—"} />
        <MiniStat label="Downloads" value={server.npm_downloads?.toLocaleString() || "—"} />
      </section>

      {/* Tools */}
      {server.tools && server.tools.length > 0 && (
        <section style={{ marginBottom: "32px" }}>
          <h2 style={{ fontSize: "18px", marginBottom: "12px" }}>
            Tools ({server.tools.length})
          </h2>
          <div
            style={{
              display: "grid",
              gap: "8px",
            }}
          >
            {server.tools.map((tool) => (
              <div
                key={tool.name}
                style={{
                  backgroundColor: "#1a1a1a",
                  border: "1px solid #333",
                  borderRadius: "6px",
                  padding: "12px",
                }}
              >
                <strong style={{ fontSize: "14px" }}>{tool.name}</strong>
                {tool.description && (
                  <p style={{ color: "#888", fontSize: "13px", margin: "4px 0 0" }}>
                    {tool.description}
                  </p>
                )}
                {tool.capability_tags?.length > 0 && (
                  <div style={{ display: "flex", gap: "4px", marginTop: "6px" }}>
                    {tool.capability_tags.map((tag) => (
                      <span
                        key={tag}
                        style={{
                          backgroundColor: "#2a2a2a",
                          padding: "2px 6px",
                          borderRadius: "3px",
                          fontSize: "11px",
                          color: "#aaa",
                        }}
                      >
                        {tag}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Findings */}
      {server.findings && server.findings.length > 0 && (
        <section style={{ marginBottom: "32px" }}>
          <h2 style={{ fontSize: "18px", marginBottom: "12px" }}>
            Security Findings ({server.findings.length})
          </h2>
          <div style={{ display: "grid", gap: "8px" }}>
            {server.findings.map((finding, i) => (
              <div
                key={i}
                style={{
                  backgroundColor: "#1a1a1a",
                  border: "1px solid #333",
                  borderRadius: "6px",
                  padding: "12px",
                }}
              >
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "8px",
                    marginBottom: "6px",
                  }}
                >
                  <SeverityBadge severity={finding.severity} />
                  <span style={{ fontSize: "14px", fontWeight: 600 }}>
                    {finding.rule_id}
                  </span>
                  {finding.owasp_category && (
                    <span style={{ fontSize: "12px", color: "#888" }}>
                      {finding.owasp_category}
                    </span>
                  )}
                </div>
                <p style={{ color: "#ccc", fontSize: "13px", margin: "0 0 6px" }}>
                  {finding.evidence}
                </p>
                <p style={{ color: "#888", fontSize: "12px", margin: 0 }}>
                  Fix: {finding.remediation}
                </p>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Badge Embed */}
      <section>
        <h2 style={{ fontSize: "18px", marginBottom: "12px" }}>Badge</h2>
        <div
          style={{
            backgroundColor: "#1a1a1a",
            border: "1px solid #333",
            borderRadius: "6px",
            padding: "12px",
          }}
        >
          <p style={{ fontSize: "13px", color: "#888", margin: "0 0 8px" }}>
            Add this badge to your README:
          </p>
          <code
            style={{
              display: "block",
              backgroundColor: "#0a0a0a",
              padding: "8px",
              borderRadius: "4px",
              fontSize: "12px",
              overflowX: "auto",
            }}
          >
            {`[![MCP Sentinel](${API_URL}/api/v1/servers/${server.slug}/badge.svg)](https://mcp-sentinel.com/server/${server.slug})`}
          </code>
        </div>
      </section>
    </div>
  );
}

function MiniStat({ label, value }: { label: string; value: string }) {
  return (
    <div
      style={{
        backgroundColor: "#1a1a1a",
        border: "1px solid #333",
        borderRadius: "6px",
        padding: "12px",
        textAlign: "center",
      }}
    >
      <div style={{ fontSize: "18px", fontWeight: 600 }}>{value}</div>
      <div style={{ color: "#888", fontSize: "12px" }}>{label}</div>
    </div>
  );
}
