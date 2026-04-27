/**
 * Preview /methodology — single canonical home for product-level depth.
 *
 * Today the same content is split across /taxonomy, /compliance, and the
 * second half of /about. Visitors looking for "how does Sentinel decide"
 * have to know which page covers which dimension.
 *
 * This page presents one IA slot with four sub-sections (Rules, Scoring,
 * Frameworks, Pipeline). Each links out to the existing live page that
 * already contains the deep content — no content is duplicated, no live
 * page is broken. Folding the content into native sub-routes is a separate
 * follow-up PR.
 */

import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Methodology",
  description:
    "How Sentinel decides — rules, scoring, framework mappings, pipeline. Preview information architecture.",
};

interface MethodologySection {
  title: string;
  oneLiner: string;
  liveHref: string;
  liveLabel: string;
  bullets: string[];
}

const SECTIONS: MethodologySection[] = [
  {
    title: "Detection rules",
    oneLiner:
      "163 deterministic detection rules across 17 categories (A–Q). Every active rule is a TypedRuleV2 implementation backed by AST taint, capability graph, entropy, similarity, or structural analysis — no regex-only detection remains.",
    liveHref: "/taxonomy",
    liveLabel: "Browse the rule taxonomy",
    bullets: [
      "Each rule produces findings with a structured EvidenceChain (source → propagation → sink → mitigation → impact).",
      "14 retired rules are kept on disk with enabled: false — they produce no findings and do not affect scores.",
      "Every rule is verified by ≥3 true-positive and ≥2 true-negative fixtures plus per-rule unit tests in CI.",
    ],
  },
  {
    title: "Scoring algorithm",
    oneLiner:
      "Score = 100 minus the sum of weighted severity penalties, with a hard cap at 40 if the lethal trifecta (F1) or the cross-config trifecta (I13) is detected.",
    liveHref: "/about",
    liveLabel: "Read the scoring section in About",
    bullets: [
      "Critical −25 · High −15 · Medium −8 · Low −3 · Informational −1.",
      "Five legacy sub-scores (Code, Deps, Config, Description, Behavior) plus eight v2 sub-scores currently shadowed in the engine.",
      "Floor 0, ceiling 100. Every score is reproducible from the input findings.",
    ],
  },
  {
    title: "Framework mappings",
    oneLiner:
      "Every rule is mapped to OWASP MCP Top 10, OWASP Agentic Top 10, MITRE ATLAS, NIST AI RMF, ISO 27001, ISO 42001, EU AI Act, CoSAI MCP Security, and MAESTRO.",
    liveHref: "/compliance",
    liveLabel: "See the framework matrix",
    bullets: [
      "Every finding carries the OWASP and MITRE identifiers it triggers.",
      "Phase 5 emits regulator-facing signed compliance reports per framework (HMAC-SHA256, RFC 8785 canonicalized).",
      "Compliance scans run a separate adversarial-test pipeline gated by ADR-009.",
    ],
  },
  {
    title: "Pipeline",
    oneLiner:
      "Discovery → Connection → Analysis → Scoring → Cross-server (Risk Matrix → Attack Graph) → Publication. Each stage is its own package with a Zod-typed contract.",
    liveHref: "/about",
    liveLabel: "Read the pipeline section in About",
    bullets: [
      "Connector calls initialize and tools/list only — never invokes a tool (ADR-007).",
      "Findings and scores are append-only (ADR-008). Score history is queryable per server.",
      "All analysis is deterministic. The single LLM exception (ADR-009) is scoped to the compliance-agents package.",
    ],
  },
];

export default function PreviewMethodologyPage() {
  return (
    <>
      <section style={{ padding: "var(--s8) 0 var(--s5)" }}>
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
          Methodology · One canonical place
        </p>
        <h1
          style={{
            fontFamily: "var(--font-body)",
            fontSize: "clamp(28px, 4vw, 40px)",
            fontWeight: 700,
            letterSpacing: "-0.03em",
            color: "var(--text)",
            marginBottom: "var(--s3)",
            maxWidth: "780px",
          }}
        >
          How Sentinel decides
        </h1>
        <p
          style={{
            fontSize: "15px",
            color: "var(--text-2)",
            lineHeight: 1.6,
            maxWidth: "680px",
          }}
        >
          Rules, scoring, framework mappings, and pipeline architecture — the
          product-level depth that today is split across three live pages.
          Each section below links to the existing live surface; consolidation
          into native sub-routes is a separate follow-up.
        </p>
      </section>

      <section
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(420px, 1fr))",
          gap: "var(--s4)",
          padding: "var(--s5) 0",
        }}
      >
        {SECTIONS.map((s) => (
          <article
            key={s.title}
            style={{
              padding: "var(--s5)",
              background: "var(--surface)",
              border: "1px solid var(--border)",
              borderRadius: "var(--r-lg)",
              display: "flex",
              flexDirection: "column",
              gap: "var(--s4)",
            }}
          >
            <header>
              <h2
                style={{
                  fontFamily: "var(--font-body)",
                  fontSize: "20px",
                  fontWeight: 700,
                  letterSpacing: "-0.02em",
                  color: "var(--text)",
                  marginBottom: "var(--s3)",
                }}
              >
                {s.title}
              </h2>
              <p
                style={{
                  fontSize: "14px",
                  color: "var(--text-2)",
                  lineHeight: 1.6,
                }}
              >
                {s.oneLiner}
              </p>
            </header>

            <ul
              style={{
                listStyle: "none",
                padding: 0,
                margin: 0,
                display: "flex",
                flexDirection: "column",
                gap: "10px",
              }}
            >
              {s.bullets.map((b) => (
                <li
                  key={b}
                  style={{
                    fontSize: "13px",
                    color: "var(--text-2)",
                    lineHeight: 1.55,
                    paddingLeft: "16px",
                    position: "relative",
                  }}
                >
                  <span
                    aria-hidden="true"
                    style={{
                      position: "absolute",
                      left: 0,
                      top: "8px",
                      width: "6px",
                      height: "6px",
                      borderRadius: "50%",
                      background: "var(--accent)",
                    }}
                  />
                  {b}
                </li>
              ))}
            </ul>

            <footer
              style={{
                paddingTop: "var(--s3)",
                borderTop: "1px solid var(--border)",
                marginTop: "auto",
              }}
            >
              <a
                href={s.liveHref}
                style={{
                  fontFamily: "var(--font-mono)",
                  fontSize: "12px",
                  color: "var(--accent-2)",
                  textDecoration: "none",
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "6px",
                }}
              >
                {s.liveLabel} →
              </a>
            </footer>
          </article>
        ))}
      </section>

      <section
        style={{
          marginTop: "var(--s6)",
          padding: "var(--s5)",
          background: "var(--surface-2)",
          border: "1px solid var(--border)",
          borderRadius: "var(--r-lg)",
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
          What this preview does not change
        </p>
        <p
          style={{
            fontSize: "13px",
            color: "var(--text-2)",
            lineHeight: 1.6,
          }}
        >
          The live methodology pages — <code>/taxonomy</code>,{" "}
          <code>/compliance</code>, <code>/about</code> — continue to render
          unchanged. This page only proposes a single nav slot they could
          consolidate into.
        </p>
      </section>
    </>
  );
}
