/**
 * Preview home — anchor for the proposed information architecture.
 *
 * Five IA slots, one purpose each, no duplicates. Visitors who arrive here
 * can reach every part of the site through exactly one navigation path.
 *
 * Data fetching policy: same API contract as the live home, so the page
 * works against the same `/api/v1/ecosystem/stats` endpoint and degrades
 * gracefully when the API is unreachable.
 */

import type { Metadata } from "next";

export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Preview — MCP Sentinel",
  description:
    "Experimental information architecture for the MCP Sentinel registry. Five IA slots, one purpose each.",
};

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3100";

interface EcosystemStats {
  total_servers: number;
  total_scanned: number;
  category_breakdown: Record<string, number>;
  severity_breakdown: Record<string, number>;
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

interface IaSlot {
  href: string;
  label: string;
  question: string;
  description: string;
  liveSurface: string;
}

const IA_SLOTS: IaSlot[] = [
  {
    href: "/preview/servers",
    label: "Servers",
    question: "Should I trust this server?",
    description:
      "The canonical list. One row per server, score visible at the row level, filterable by category, language, score range, and source.",
    liveSurface: "Replaces /servers and the listing duplication on the live home",
  },
  {
    href: "/preview/ecosystem",
    label: "Ecosystem",
    question: "What does the MCP universe look like?",
    description:
      "Live posture across every scanned server: category breakdown, severity distribution, scan coverage, recently-discovered servers.",
    liveSurface: "Promotes /dashboard into the navigation",
  },
  {
    href: "/preview/intelligence",
    label: "Intelligence",
    question: "What attacks are happening, and where?",
    description:
      "Kill chains, drift, lethal trifectas, CVE replay corpus, competitive benchmark — the differentiated data layer surfaced as one section.",
    liveSurface: "Promotes /attack-chains into the navigation",
  },
  {
    href: "/preview/methodology",
    label: "Methodology",
    question: "How does Sentinel decide?",
    description:
      "Detection rules, scoring algorithm, framework mappings, pipeline architecture, responsible disclosure. One canonical place for product-level depth.",
    liveSurface: "Consolidates /taxonomy + /compliance + parts of /about",
  },
  {
    href: "/preview/scanner",
    label: "Scanner",
    question: "How do I run this on my own servers?",
    description:
      "npx mcp-sentinel-scanner — install, expected output, safety guarantees, supported MCP clients.",
    liveSurface: "Mirrors /scanner — content trim is a follow-up PR",
  },
];

export default async function PreviewHome() {
  const stats = await getStats();

  return (
    <>
      {/* ── Hero ──────────────────────────────────────────── */}
      <section
        style={{
          padding: "var(--s10) 0 var(--s8)",
          textAlign: "left",
        }}
      >
        <p
          style={{
            fontFamily: "var(--font-mono)",
            fontSize: "12px",
            letterSpacing: "0.06em",
            textTransform: "uppercase",
            color: "var(--accent-2)",
            marginBottom: "var(--s4)",
          }}
        >
          Information Architecture · Preview
        </p>
        <h1
          style={{
            fontFamily: "var(--font-body)",
            fontSize: "clamp(36px, 6vw, 56px)",
            fontWeight: 800,
            letterSpacing: "-0.04em",
            lineHeight: 1.05,
            color: "var(--text)",
            marginBottom: "var(--s5)",
            maxWidth: "780px",
          }}
        >
          Five sections. One purpose each. No duplicates.
        </h1>
        <p
          style={{
            fontSize: "17px",
            color: "var(--text-2)",
            lineHeight: 1.6,
            maxWidth: "640px",
          }}
        >
          The live registry has fourteen pages, four of which duplicate work
          and the most differentiated screens are missing from the navigation.
          This preview proposes a navigation where every visitor question maps
          to exactly one destination.
        </p>
      </section>

      {/* ── Ground-truth stats strip ──────────────────────── */}
      <section
        aria-label="Ecosystem snapshot"
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
          gap: "var(--s4)",
          padding: "var(--s5) 0 var(--s8)",
          borderTop: "1px solid var(--border)",
          borderBottom: "1px solid var(--border)",
        }}
      >
        <Stat
          label="Servers discovered"
          value={stats ? stats.total_servers.toLocaleString() : "—"}
        />
        <Stat
          label="Servers scanned"
          value={stats ? stats.total_scanned.toLocaleString() : "—"}
        />
        <Stat label="Active detection rules" value="163" />
        <Stat label="Categories" value="17" />
        <Stat
          label="Critical findings"
          value={
            stats?.severity_breakdown?.critical?.toLocaleString() ?? "—"
          }
          accent="critical"
        />
      </section>

      {/* ── IA proposal grid ──────────────────────────────── */}
      <section style={{ padding: "var(--s8) 0" }}>
        <h2
          style={{
            fontFamily: "var(--font-body)",
            fontSize: "13px",
            fontWeight: 600,
            letterSpacing: "0.06em",
            textTransform: "uppercase",
            color: "var(--text-3)",
            marginBottom: "var(--s5)",
          }}
        >
          The five slots
        </h2>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))",
            gap: "var(--s4)",
          }}
        >
          {IA_SLOTS.map((slot) => (
            <a
              key={slot.href}
              href={slot.href}
              style={{
                display: "block",
                padding: "var(--s5)",
                background: "var(--surface)",
                border: "1px solid var(--border)",
                borderRadius: "var(--r-lg)",
                textDecoration: "none",
                transition:
                  "border-color 120ms ease, transform 120ms ease, box-shadow 120ms ease",
              }}
            >
              <p
                style={{
                  fontFamily: "var(--font-mono)",
                  fontSize: "11px",
                  letterSpacing: "0.06em",
                  textTransform: "uppercase",
                  color: "var(--accent-2)",
                  marginBottom: "var(--s3)",
                }}
              >
                {slot.label}
              </p>
              <p
                style={{
                  fontSize: "18px",
                  fontWeight: 600,
                  letterSpacing: "-0.01em",
                  color: "var(--text)",
                  marginBottom: "var(--s3)",
                }}
              >
                {slot.question}
              </p>
              <p
                style={{
                  fontSize: "14px",
                  color: "var(--text-2)",
                  lineHeight: 1.55,
                  marginBottom: "var(--s4)",
                }}
              >
                {slot.description}
              </p>
              <p
                style={{
                  fontFamily: "var(--font-mono)",
                  fontSize: "11px",
                  color: "var(--text-3)",
                  borderTop: "1px solid var(--border)",
                  paddingTop: "var(--s3)",
                }}
              >
                {slot.liveSurface}
              </p>
            </a>
          ))}
        </div>
      </section>

      {/* ── Honest disclosure ─────────────────────────────── */}
      <section
        style={{
          padding: "var(--s6)",
          background: "var(--surface-2)",
          border: "1px solid var(--border)",
          borderRadius: "var(--r-lg)",
          marginTop: "var(--s6)",
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
          What works today
        </p>
        <p
          style={{
            fontSize: "14px",
            color: "var(--text-2)",
            lineHeight: 1.6,
          }}
        >
          The chrome (banner, navigation, footer) is final. The{" "}
          <a
            href="/preview/servers"
            style={{ color: "var(--accent-2)", textDecoration: "underline" }}
          >
            Servers list
          </a>
          {" "}and{" "}
          <a
            href="/preview/methodology"
            style={{ color: "var(--accent-2)", textDecoration: "underline" }}
          >
            Methodology landing
          </a>
          {" "}are functional. Other slots currently route to their live
          equivalents (kept fully working, never broken). Each will be
          consolidated in its own follow-up PR. The live site at{" "}
          <a href="/" style={{ color: "var(--accent-2)", textDecoration: "underline" }}>
            mcp-sentinel.com
          </a>
          {" "}is unaffected.
        </p>
      </section>
    </>
  );
}

function Stat({
  label,
  value,
  accent,
}: {
  label: string;
  value: string;
  accent?: "critical";
}) {
  return (
    <div>
      <p
        style={{
          fontFamily: "var(--font-mono)",
          fontSize: "28px",
          fontWeight: 600,
          letterSpacing: "-0.02em",
          color: accent === "critical" ? "var(--critical)" : "var(--text)",
          marginBottom: "4px",
        }}
      >
        {value}
      </p>
      <p
        style={{
          fontSize: "12px",
          color: "var(--text-3)",
          letterSpacing: "0.02em",
        }}
      >
        {label}
      </p>
    </div>
  );
}
