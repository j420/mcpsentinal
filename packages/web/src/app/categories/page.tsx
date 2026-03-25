import type { Metadata } from "next";

export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Browse by Category",
  description:
    "Explore MCP servers organised by category. Browse database connectors, filesystem tools, API integrations, AI/ML servers, and more.",
};

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3100";

// ── Types ─────────────────────────────────────────────────────────────────────

interface EcosystemStats {
  total_servers: number;
  total_scanned: number;
  category_breakdown: Record<string, number>;
}

// ── Category metadata ──────────────────────────────────────────────────────────

const CATEGORY_META: Record<
  string,
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
    label: "Cloud Infrastructure",
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

const CATEGORY_ORDER = [
  "database",
  "filesystem",
  "api-integration",
  "dev-tools",
  "ai-ml",
  "browser-web",
  "code-execution",
  "communication",
  "cloud-infra",
  "security",
  "data-processing",
  "monitoring",
  "search",
  "other",
];

// ── Data fetching ──────────────────────────────────────────────────────────────

async function getStats(): Promise<EcosystemStats | null> {
  try {
    const res = await fetch(`${API_URL}/api/v1/ecosystem/stats`, {
      signal: AbortSignal.timeout(4000),
      next: { revalidate: 3600 },
    });
    if (!res.ok) return null;
    const data = await res.json();
    return data.data ?? null;
  } catch {
    return null;
  }
}

// ── SVG Icons ─────────────────────────────────────────────────────────────────

function DatabaseIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <ellipse cx="10" cy="5" rx="7" ry="2.5" />
      <path d="M3 5v4c0 1.38 3.13 2.5 7 2.5S17 10.38 17 9V5" />
      <path d="M3 9v4c0 1.38 3.13 2.5 7 2.5S17 14.38 17 13V9" />
    </svg>
  );
}

function FilesystemIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M3 6a1 1 0 011-1h4l2 2h6a1 1 0 011 1v7a1 1 0 01-1 1H4a1 1 0 01-1-1V6z" />
    </svg>
  );
}

function ApiIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
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
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="5 8 2 10 5 12" />
      <polyline points="15 8 18 10 15 12" />
      <line x1="11" y1="5" x2="9" y2="15" />
    </svg>
  );
}

function AiMlIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round">
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
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M17 10c0 3.31-3.13 6-7 6a7.87 7.87 0 01-3-.58L3 17l1.07-3.07A5.78 5.78 0 013 10c0-3.31 3.13-6 7-6s7 2.69 7 6z" />
    </svg>
  );
}

function CloudInfraIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M16 13.5a3.5 3.5 0 00-3.5-3.5 3.5 3.5 0 00-3.4-2.7 3.5 3.5 0 00-3.5 3.5H5a2.5 2.5 0 000 5h10.5a2.5 2.5 0 000-5H16z" />
    </svg>
  );
}

function SecurityIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10 2L17 5v5c0 4.5-3 8-7 9.5C6 18 3 14.5 3 10V5l7-3z" />
      <polyline points="7 10 9 12 13 8" />
    </svg>
  );
}

function DataProcessingIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="3 6 10 3 17 6" />
      <line x1="10" y1="3"  x2="10" y2="11" />
      <path d="M5 8.5v5l5 2.5 5-2.5v-5" />
    </svg>
  );
}

function MonitoringIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="3 14 7 9 10 12 13 7 17 11" />
      <rect x="2" y="3" width="16" height="14" rx="1.5" />
    </svg>
  );
}

function SearchIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
      <circle cx="8.5" cy="8.5" r="5.5" />
      <path d="M13.5 13.5L17 17" />
    </svg>
  );
}

function BrowserWebIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="10" cy="10" r="7.5" />
      <path d="M2.5 10h15" />
      <path d="M10 2.5c-2 2.5-2 12.5 0 15" />
      <path d="M10 2.5c2 2.5 2 12.5 0 15" />
    </svg>
  );
}

function CodeExecutionIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="6 8 2 12 6 16" />
      <polyline points="14 8 18 12 14 16" />
      <line x1="11" y1="6" x2="9" y2="18" />
    </svg>
  );
}

function OtherIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
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

export default async function CategoriesPage() {
  const stats = await getStats();
  const breakdown = stats?.category_breakdown ?? {};

  // Sort CATEGORY_ORDER by server count descending, keeping unknowns at the end
  const sorted = [...CATEGORY_ORDER].sort((a, b) => {
    const ca = breakdown[a] ?? 0;
    const cb = breakdown[b] ?? 0;
    if (a === "other") return 1;
    if (b === "other") return -1;
    return cb - ca;
  });

  const totalCategorised = Object.values(breakdown).reduce((s, n) => s + n, 0);

  return (
    <>
      {/* ── Header ──────────────────────────────────────────── */}
      <div style={{ paddingTop: "var(--s10)", paddingBottom: "var(--s6)" }}>
        <a
          href="/"
          style={{ fontSize: "13px", color: "var(--text-3)", display: "inline-flex", alignItems: "center", gap: "6px", marginBottom: "var(--s5)" }}
        >
          <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
            <path d="M10 3L5 8l5 5" />
          </svg>
          Registry
        </a>

        <div style={{ display: "flex", alignItems: "baseline", gap: "var(--s3)", flexWrap: "wrap", marginBottom: "var(--s3)" }}>
          <h1
            style={{
              fontFamily: "var(--font-body)",
              fontSize: "clamp(28px, 5vw, 42px)",
              fontWeight: 800,
              letterSpacing: "-0.04em",
              lineHeight: 1.05,
              color: "var(--text)",
            }}
          >
            Browse by Category
          </h1>
          {stats && (
            <span
              style={{
                fontSize: "14px",
                color: "var(--text-3)",
                fontWeight: 500,
              }}
            >
              {Object.keys(breakdown).length} categories · {totalCategorised.toLocaleString()} servers
            </span>
          )}
        </div>

        <p style={{ fontSize: "15px", color: "var(--text-2)", maxWidth: "560px", lineHeight: 1.6 }}>
          Every category is analysed for security findings. High-risk categories and servers with
          critical findings are surfaced first.
        </p>
      </div>

      {/* ── Category grid ───────────────────────────────────── */}
      <div className="cat-grid" role="list" aria-label="Server categories">
        {sorted.map((slug) => {
          const meta = CATEGORY_META[slug];
          if (!meta) return null;
          const count = breakdown[slug] ?? 0;

          return (
            <a
              key={slug}
              href={`/categories/${slug}`}
              className="cat-card"
              role="listitem"
              aria-label={`${meta.label}: ${count} servers`}
            >
              <div className="cat-card-head">
                <div className="cat-icon" aria-hidden="true">
                  {meta.icon}
                </div>
                <span className="cat-name">{meta.label}</span>
              </div>

              <p className="cat-desc">{meta.description}</p>

              <div className="cat-risk" title="Primary security risks in this category">
                ⚠ {meta.riskNote}
              </div>

              <div className="cat-footer">
                <span className="cat-count">
                  {count > 0 ? `${count.toLocaleString()} server${count !== 1 ? "s" : ""}` : "No data yet"}
                </span>
                <span className="cat-cta">
                  Browse
                  <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                    <path d="M6 3l5 5-5 5" />
                  </svg>
                </span>
              </div>
            </a>
          );
        })}
      </div>

      {/* ── All-servers CTA ─────────────────────────────────── */}
      <div
        style={{
          marginTop: "var(--s12)",
          padding: "var(--s6)",
          background: "var(--surface)",
          border: "1px solid var(--border)",
          borderRadius: "var(--r-lg)",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          flexWrap: "wrap",
          gap: "var(--s4)",
        }}
      >
        <div>
          <p style={{ fontWeight: 600, color: "var(--text)", marginBottom: "4px" }}>
            Looking for something specific?
          </p>
          <p style={{ fontSize: "13px", color: "var(--text-2)" }}>
            Search across all categories with filters, score ranges, and sort options.
          </p>
        </div>
        <a
          href="/"
          className="btn-primary"
          style={{ padding: "9px 20px", fontSize: "14px", whiteSpace: "nowrap" }}
        >
          Search all servers
        </a>
      </div>
    </>
  );
}
