import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "About MCP Sentinel",
  description:
    "How MCP Sentinel works: 83 deterministic detection rules across 10 categories, a 4-stage scan pipeline, and the scoring algorithm that produces every security score.",
};

// ── Rule categories ───────────────────────────────────────────────────────────

const RULE_CATEGORIES = [
  {
    code: "A",
    name: "Description Analysis",
    count: 9,
    requires: "Tool metadata",
    highlight: "Unicode homoglyph attacks, zero-width character injection, base64-encoded payloads hidden from human review",
    rules: [
      { id: "A1", name: "Prompt Injection in Description", sev: "critical" },
      { id: "A2", name: "Excessive Scope Claims", sev: "high" },
      { id: "A3", name: "Suspicious URLs", sev: "medium" },
      { id: "A4", name: "Cross-Server Tool Name Shadowing", sev: "high" },
      { id: "A5", name: "Description Length Anomaly", sev: "low" },
      { id: "A6", name: "Unicode Homoglyph Attack", sev: "critical" },
      { id: "A7", name: "Zero-Width Character Injection", sev: "critical" },
      { id: "A8", name: "Description–Capability Mismatch", sev: "high" },
      { id: "A9", name: "Encoded Instructions in Description", sev: "critical" },
    ],
  },
  {
    code: "B",
    name: "Schema Analysis",
    count: 7,
    requires: "Tool metadata",
    highlight: "Parameter-level injection surface, dangerous defaults (recursive:true, disable_ssl_verify:true), unconstrained additional properties",
    rules: [
      { id: "B1", name: "Missing Input Validation", sev: "medium" },
      { id: "B2", name: "Dangerous Parameter Types", sev: "high" },
      { id: "B3", name: "Excessive Parameter Count", sev: "low" },
      { id: "B4", name: "Schema-less Tools", sev: "medium" },
      { id: "B5", name: "Prompt Injection in Parameter Description", sev: "critical" },
      { id: "B6", name: "Unconstrained Additional Properties", sev: "medium" },
      { id: "B7", name: "Dangerous Default Parameter Values", sev: "high" },
    ],
  },
  {
    code: "C",
    name: "Code Analysis",
    count: 16,
    requires: "Source code",
    highlight: "20+ secret token formats, prototype pollution, unsafe deserialization, JWT algorithm confusion, timing attacks on secret comparison",
    rules: [
      { id: "C1", name: "Command Injection", sev: "critical" },
      { id: "C2", name: "Path Traversal", sev: "critical" },
      { id: "C3", name: "SSRF", sev: "high" },
      { id: "C4", name: "SQL Injection", sev: "critical" },
      { id: "C5", name: "Hardcoded Secrets (20+ formats)", sev: "critical" },
      { id: "C6", name: "Error Leakage", sev: "medium" },
      { id: "C7", name: "Wildcard CORS", sev: "high" },
      { id: "C8", name: "No Auth on Network Interface", sev: "high" },
      { id: "C9", name: "Excessive Filesystem Scope", sev: "high" },
      { id: "C10", name: "Prototype Pollution", sev: "critical" },
      { id: "C11", name: "ReDoS Vulnerability", sev: "high" },
      { id: "C12", name: "Unsafe Deserialization", sev: "critical" },
      { id: "C13", name: "Server-Side Template Injection", sev: "critical" },
      { id: "C14", name: "JWT Algorithm Confusion", sev: "critical" },
      { id: "C15", name: "Timing Attack on Secret Comparison", sev: "high" },
      { id: "C16", name: "Dynamic Code Evaluation", sev: "critical" },
    ],
  },
  {
    code: "D",
    name: "Dependency Analysis",
    count: 7,
    requires: "package.json / requirements.txt",
    highlight: "50+ confirmed malicious package names including MCP ecosystem typosquats, Levenshtein distance for typosquat detection, dependency confusion (high version number trick)",
    rules: [
      { id: "D1", name: "Known CVEs in Dependencies", sev: "high" },
      { id: "D2", name: "Abandoned Dependencies", sev: "medium" },
      { id: "D3", name: "Typosquatting Risk", sev: "high" },
      { id: "D4", name: "Excessive Dependency Count", sev: "low" },
      { id: "D5", name: "Known Malicious Packages", sev: "critical" },
      { id: "D6", name: "Weak Cryptography Dependencies", sev: "high" },
      { id: "D7", name: "Dependency Confusion Attack Risk", sev: "high" },
    ],
  },
  {
    code: "E",
    name: "Behavioral Analysis",
    count: 4,
    requires: "Connection metadata",
    highlight: "Live connection checks — transport security, authentication presence, response time anomalies, tool count explosion",
    rules: [
      { id: "E1", name: "No Authentication Required", sev: "medium" },
      { id: "E2", name: "Insecure Transport (HTTP/WS)", sev: "high" },
      { id: "E3", name: "Response Time Anomaly (>10s)", sev: "low" },
      { id: "E4", name: "Excessive Tool Count (>50)", sev: "medium" },
    ],
  },
  {
    code: "F",
    name: "Ecosystem Context",
    count: 7,
    requires: "Tool metadata",
    highlight: "Lethal Trifecta (private data + untrusted input + external comms = score capped at 40), circular data loop enabling persistent injection, multi-step exfiltration chain",
    rules: [
      { id: "F1", name: "Lethal Trifecta", sev: "critical" },
      { id: "F2", name: "High-Risk Capability Profile", sev: "medium" },
      { id: "F3", name: "Data Flow Risk Source→Sink", sev: "high" },
      { id: "F4", name: "MCP Spec Non-Compliance", sev: "low" },
      { id: "F5", name: "Official Namespace Squatting", sev: "critical" },
      { id: "F6", name: "Circular Data Loop", sev: "high" },
      { id: "F7", name: "Multi-Step Exfiltration Chain", sev: "critical" },
    ],
  },
  {
    code: "G",
    name: "Adversarial AI",
    count: 7,
    requires: "Tool metadata + scan history",
    highlight: "Attacks that only work because the target is an AI — indirect injection gateways, trust assertion injection, tool behavior drift (rug pull), DNS data exfiltration",
    rules: [
      { id: "G1", name: "Indirect Prompt Injection Gateway", sev: "critical" },
      { id: "G2", name: "Trust Assertion Injection", sev: "critical" },
      { id: "G3", name: "Tool Response Format Injection", sev: "critical" },
      { id: "G4", name: "Context Window Saturation", sev: "high" },
      { id: "G5", name: "Capability Escalation via Prior Approval", sev: "critical" },
      { id: "G6", name: "Rug Pull / Tool Behavior Drift", sev: "critical" },
      { id: "G7", name: "DNS-Based Data Exfiltration Channel", sev: "critical" },
    ],
  },
  {
    code: "H",
    name: "2026 Attack Surface",
    count: 3,
    requires: "Mixed",
    highlight: "March 2026 additions: OAuth 2.0 MCP auth flaws, injection into MCP initialize response fields (processed before tool descriptions), cross-agent propagation in multi-agent orchestration",
    rules: [
      { id: "H1", name: "MCP OAuth 2.0 Insecure Implementation", sev: "critical" },
      { id: "H2", name: "Prompt Injection in Initialize Response", sev: "critical" },
      { id: "H3", name: "Multi-Agent Propagation Risk", sev: "high" },
    ],
  },
  {
    code: "I",
    name: "Protocol Surface",
    count: 16,
    requires: "Protocol metadata + annotations",
    highlight: "MCP protocol primitive attacks: annotation deception (readOnlyHint lies), sampling abuse (23-41% attack amplification), cross-config lethal trifecta, consent fatigue exploitation (84.2% success rate), credential harvesting via elicitation",
    rules: [
      { id: "I1", name: "Annotation Deception", sev: "critical" },
      { id: "I2", name: "Missing Destructive Annotation", sev: "high" },
      { id: "I3", name: "Resource Metadata Injection", sev: "critical" },
      { id: "I4", name: "Dangerous Resource URI", sev: "critical" },
      { id: "I5", name: "Resource-Tool Shadowing", sev: "high" },
      { id: "I6", name: "Prompt Template Injection", sev: "critical" },
      { id: "I7", name: "Sampling Capability Abuse", sev: "critical" },
      { id: "I8", name: "Sampling Cost Attack", sev: "high" },
      { id: "I9", name: "Elicitation Credential Harvesting", sev: "critical" },
      { id: "I10", name: "Elicitation URL Redirect", sev: "high" },
      { id: "I11", name: "Over-Privileged Root", sev: "high" },
      { id: "I12", name: "Capability Escalation Post-Init", sev: "critical" },
      { id: "I13", name: "Cross-Config Lethal Trifecta", sev: "critical" },
      { id: "I14", name: "Rolling Capability Drift", sev: "high" },
      { id: "I15", name: "Transport Session Security", sev: "high" },
      { id: "I16", name: "Consent Fatigue Exploitation", sev: "high" },
    ],
  },
  {
    code: "J",
    name: "2026 Threat Intelligence",
    count: 7,
    requires: "Source code + tool metadata",
    highlight: "CVE-backed rules from real-world incidents: cross-agent config poisoning (CVE-2025-53773), git argument injection (CVE-2025-68143), full schema poisoning (CyberArk FSP), health endpoint disclosure (CVE-2026-29787), tool output poisoning (CyberArk ATPA), OpenAPI spec injection (CVE-2026-22785)",
    rules: [
      { id: "J1", name: "Cross-Agent Config Poisoning", sev: "critical" },
      { id: "J2", name: "Git Argument Injection", sev: "critical" },
      { id: "J3", name: "Full Schema Poisoning", sev: "critical" },
      { id: "J4", name: "Health Endpoint Disclosure", sev: "high" },
      { id: "J5", name: "Tool Output Poisoning", sev: "critical" },
      { id: "J6", name: "Tool Preference Manipulation", sev: "high" },
      { id: "J7", name: "OpenAPI Spec Injection", sev: "critical" },
    ],
  },
];

const OWASP_RULES: Array<{ id: string; name: string; rules: string }> = [
  { id: "MCP01", name: "Prompt Injection", rules: "A1, A5, A7, A8, A9, B5, F1, F6, G1, G2, G3, H2, I3, I6, I7, J3, J5, J6" },
  { id: "MCP02", name: "Tool Poisoning", rules: "A2, A4, A6, F2, F5, G5, I1, I2, J5, J6" },
  { id: "MCP03", name: "Command Injection", rules: "C1, C9, C13, C16, J2, J7" },
  { id: "MCP04", name: "Data Exfiltration", rules: "A3, F1, F3, F7, G7, I9, I13" },
  { id: "MCP05", name: "Privilege Escalation", rules: "C2, C8, C10, C12, H1, I4, I12, J1" },
  { id: "MCP06", name: "Excessive Permissions", rules: "A2, B3, B7, E4, F2, I11, I16" },
  { id: "MCP07", name: "Insecure Configuration", rules: "B6, C7, C8, C11, C14, C15, D6, E1, E2, H1, I15, J4" },
  { id: "MCP08", name: "Dependency Vulnerabilities", rules: "D1, D2, D3, D4, D5, D6, D7" },
  { id: "MCP09", name: "Logging & Monitoring", rules: "C6, E3" },
  { id: "MCP10", name: "Supply Chain", rules: "D3, D5, D7, A4, F5, G6, I5, I14, J7" },
];

const PIPELINE = [
  {
    num: "01",
    name: "Discovery",
    package: "crawler",
    desc: "Crawls 6+ sources: npm, PyPI, GitHub, PulseMCP, Smithery, MCP Registry. Deduplicates by GitHub URL → npm package → name. Logs source, servers_found, new_unique, duplicates, errors, elapsed_time.",
  },
  {
    num: "02",
    name: "Connection",
    package: "connector",
    desc: "Wraps the official MCP SDK. Calls initialize and tools/list only — never invokes tools. Captures serverInfo.name, serverInfo.version, instructions field, auth method, transport, and response time.",
  },
  {
    num: "03",
    name: "Analysis",
    package: "analyzer",
    desc: "Runs 60 deterministic detection rules (YAML-defined) against tool metadata, schema, source code, dependencies, connection metadata, and initialize response. Every finding includes rule_id, evidence, and remediation.",
  },
  {
    num: "04",
    name: "Scoring",
    package: "scorer",
    desc: "Score = 100 − Σ(weighted penalties). Critical: −25, High: −15, Medium: −8, Low: −3, Info: −1. Lethal Trifecta caps total at 40. Five sub-scores track independent category health. Floor: 0, ceiling: 100.",
  },
];

// ── Helpers ───────────────────────────────────────────────────────────────────

function SevDot({ sev }: { sev: string }) {
  const colors: Record<string, string> = {
    critical: "var(--sev-critical)",
    high: "var(--sev-high)",
    medium: "var(--sev-medium)",
    low: "var(--sev-low)",
  };
  return (
    <span
      style={{
        display: "inline-block",
        width: 6,
        height: 6,
        borderRadius: "50%",
        background: colors[sev] ?? "var(--text-3)",
        flexShrink: 0,
        marginTop: 2,
      }}
    />
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function AboutPage() {
  return (
    <>
      {/* ── Hero ─────────────────────────────────────── */}
      <section className="about-hero">
        <div className="hero-eyebrow" style={{ display: "inline-flex" }}>
          About MCP Sentinel
        </div>
        <h1 className="about-h1">
          Security intelligence built
          <br />
          from data, not theory.
        </h1>
        <p className="about-lead">
          Nobody had actually measured what&apos;s happening across the MCP
          ecosystem. We built the tooling to find out — 6 crawlers, 60
          detection rules, fully deterministic, no LLMs.
        </p>
      </section>

      <div className="divider" />

      {/* ── The problem ──────────────────────────────── */}
      <section style={{ maxWidth: 680, padding: "var(--s8) 0" }}>
        <h2
          style={{
            fontSize: "22px",
            fontWeight: 700,
            letterSpacing: "-0.02em",
            marginBottom: "var(--s4)",
          }}
        >
          The problem we&apos;re solving
        </h2>
        <p style={{ fontSize: "15px", color: "var(--text-2)", lineHeight: 1.7, marginBottom: "var(--s4)" }}>
          MCP servers are granted access to files, databases, APIs, and code
          execution — often in a single{" "}
          <code style={{ color: "var(--accent)" }}>claude_desktop_config.json</code>{" "}
          edit. There is no vetting. No audit. No trust signal.
        </p>
        <p style={{ fontSize: "15px", color: "var(--text-2)", lineHeight: 1.7, marginBottom: "var(--s4)" }}>
          Every AI security framework talks about prompt injection, tool
          poisoning, and supply-chain risk in the abstract. We run 60
          concrete checks on every server we can find, store the results
          immutably, and publish them — so developers, enterprises, and
          gateway builders can make decisions from evidence, not intuition.
        </p>
        <p style={{ fontSize: "15px", color: "var(--text-2)", lineHeight: 1.7 }}>
          The data is the product. We are the security intelligence layer
          upstream of every gateway, registry, and deployment decision in
          the MCP ecosystem.
        </p>
      </section>

      <div className="divider" />

      {/* ── Pipeline ─────────────────────────────────── */}
      <section style={{ padding: "var(--s8) 0" }}>
        <h2
          style={{
            fontSize: "22px",
            fontWeight: 700,
            letterSpacing: "-0.02em",
            marginBottom: "var(--s2)",
          }}
        >
          How a scan works
        </h2>
        <p
          style={{
            fontSize: "14px",
            color: "var(--text-3)",
            marginBottom: "var(--s6)",
          }}
        >
          Four deterministic stages. Every stage is a separate package with a
          documented contract. No LLMs, no black boxes.
        </p>
        <div className="pipeline-grid">
          {PIPELINE.map((step) => (
            <div key={step.num} className="pipeline-step">
              <div className="pipeline-num">Stage {step.num}</div>
              <div className="pipeline-name">{step.name}</div>
              <div
                style={{
                  fontSize: "10px",
                  fontFamily: "var(--font-mono, monospace)",
                  color: "var(--accent)",
                  marginBottom: "var(--s2)",
                  opacity: 0.8,
                }}
              >
                @mcp-sentinel/{step.package}
              </div>
              <p className="pipeline-desc">{step.desc}</p>
            </div>
          ))}
        </div>
      </section>

      <div className="divider" />

      {/* ── 60 Detection rules ───────────────────────── */}
      <section style={{ padding: "var(--s8) 0" }}>
        <h2
          style={{
            fontSize: "22px",
            fontWeight: 700,
            letterSpacing: "-0.02em",
            marginBottom: "var(--s2)",
          }}
        >
          83 detection rules across 10 categories
        </h2>
        <p
          style={{
            fontSize: "14px",
            color: "var(--text-3)",
            marginBottom: "var(--s6)",
          }}
        >
          All rules are YAML-defined. The engine is deterministic. Adding a
          rule never requires changing engine code. Every finding requires{" "}
          <code>rule_id</code>, <code>evidence</code>, and{" "}
          <code>remediation</code>.
        </p>

        <div style={{ display: "flex", flexDirection: "column", gap: "var(--s4)" }}>
          {RULE_CATEGORIES.map((cat) => (
            <div key={cat.code} className="card">
              <div
                style={{
                  display: "flex",
                  alignItems: "flex-start",
                  justifyContent: "space-between",
                  gap: "var(--s4)",
                  marginBottom: "var(--s3)",
                }}
              >
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: "var(--s2)", marginBottom: "var(--s1)" }}>
                    <span
                      style={{
                        fontSize: "13px",
                        fontWeight: 800,
                        color: "var(--accent)",
                        fontFamily: "var(--font-mono, monospace)",
                        background: "var(--accent-sub)",
                        border: "1px solid var(--accent-ring)",
                        borderRadius: "var(--r-sm)",
                        padding: "1px 7px",
                      }}
                    >
                      {cat.code}
                    </span>
                    <h3
                      style={{
                        fontSize: "15px",
                        fontWeight: 700,
                        color: "var(--text)",
                      }}
                    >
                      {cat.name}
                    </h3>
                    <span
                      style={{
                        fontSize: "11px",
                        color: "var(--text-3)",
                        background: "var(--surface-2)",
                        border: "1px solid var(--border)",
                        borderRadius: "var(--r-full)",
                        padding: "1px 7px",
                        fontWeight: 500,
                      }}
                    >
                      {cat.count} rules
                    </span>
                  </div>
                  <p style={{ fontSize: "12px", color: "var(--text-3)" }}>
                    Requires: {cat.requires}
                  </p>
                </div>
              </div>

              <p
                style={{
                  fontSize: "13px",
                  color: "var(--text-2)",
                  lineHeight: 1.55,
                  marginBottom: "var(--s4)",
                  padding: "var(--s3)",
                  background: "var(--surface-2)",
                  borderRadius: "var(--r-sm)",
                  borderLeft: "2px solid var(--accent)",
                }}
              >
                {cat.highlight}
              </p>

              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))",
                  gap: "var(--s1)",
                }}
              >
                {cat.rules.map((rule) => (
                  <div
                    key={rule.id}
                    style={{
                      display: "flex",
                      alignItems: "flex-start",
                      gap: "var(--s2)",
                      padding: "var(--s2)",
                    }}
                  >
                    <SevDot sev={rule.sev} />
                    <span
                      style={{
                        fontSize: "11px",
                        fontWeight: 700,
                        color: "var(--text-3)",
                        fontFamily: "var(--font-mono, monospace)",
                        flexShrink: 0,
                      }}
                    >
                      {rule.id}
                    </span>
                    <span style={{ fontSize: "12px", color: "var(--text-2)" }}>
                      {rule.name}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </section>

      <div className="divider" />

      {/* ── OWASP MCP Top 10 mapping ─────────────────── */}
      <section style={{ padding: "var(--s8) 0" }}>
        <h2
          style={{
            fontSize: "22px",
            fontWeight: 700,
            letterSpacing: "-0.02em",
            marginBottom: "var(--s2)",
          }}
        >
          OWASP MCP Top 10 mapping
        </h2>
        <p
          style={{
            fontSize: "14px",
            color: "var(--text-3)",
            marginBottom: "var(--s5)",
          }}
        >
          Every rule is mapped to the OWASP MCP Top 10. A server&apos;s OWASP
          coverage score shows whether any findings were detected in each
          category.
        </p>
        <table className="rules-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Category</th>
              <th>Rules</th>
            </tr>
          </thead>
          <tbody>
            {OWASP_RULES.map((row) => (
              <tr key={row.id}>
                <td>
                  <span
                    style={{
                      fontFamily: "var(--font-mono, monospace)",
                      fontWeight: 700,
                      color: "var(--accent)",
                      fontSize: "12px",
                    }}
                  >
                    {row.id}
                  </span>
                </td>
                <td style={{ fontWeight: 500, color: "var(--text)" }}>
                  {row.name}
                </td>
                <td>
                  <span
                    style={{
                      fontFamily: "var(--font-mono, monospace)",
                      fontSize: "12px",
                      color: "var(--text-3)",
                    }}
                  >
                    {row.rules}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <div className="divider" />

      {/* ── Scoring ──────────────────────────────────── */}
      <section style={{ padding: "var(--s8) 0" }}>
        <h2
          style={{
            fontSize: "22px",
            fontWeight: 700,
            letterSpacing: "-0.02em",
            marginBottom: "var(--s5)",
          }}
        >
          Scoring algorithm
        </h2>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: "var(--s5)",
          }}
        >
          <div className="card">
            <h3 style={{ fontSize: "14px", fontWeight: 700, marginBottom: "var(--s3)" }}>
              Formula
            </h3>
            <pre
              className="badge-embed"
              style={{ fontSize: "14px", whiteSpace: "pre-wrap" }}
            >{`Score = 100 − Σ(weighted penalties)

Severity  →  Penalty
Critical  →  −25
High      →  −15
Medium    →  −8
Low       →  −3
Info      →  −1

Floor: 0  |  Ceiling: 100`}</pre>
          </div>
          <div className="card">
            <h3 style={{ fontSize: "14px", fontWeight: 700, marginBottom: "var(--s3)" }}>
              Special rules
            </h3>
            <div style={{ display: "flex", flexDirection: "column", gap: "var(--s3)" }}>
              <div>
                <div style={{ fontSize: "13px", fontWeight: 600, color: "var(--critical)", marginBottom: "var(--s1)" }}>
                  Lethal Trifecta (F1)
                </div>
                <p style={{ fontSize: "13px", color: "var(--text-3)", lineHeight: 1.55 }}>
                  If a server reads private data AND ingests untrusted content
                  AND has external network access, its total score is{" "}
                  <strong style={{ color: "var(--text-2)" }}>capped at 40</strong>{" "}
                  regardless of other findings. No amount of clean code
                  compensates for this combination.
                </p>
              </div>
              <div>
                <div style={{ fontSize: "13px", fontWeight: 600, color: "var(--text-2)", marginBottom: "var(--s1)" }}>
                  Sub-scores
                </div>
                <p style={{ fontSize: "13px", color: "var(--text-3)", lineHeight: 1.55 }}>
                  Code, Dependencies, Config, Description, and Behavior scores
                  are computed independently. A server can have a poor Code
                  score but a clean Dependencies score — the breakdown is
                  always shown on the detail page.
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      <div className="divider" />

      {/* ── Principles ───────────────────────────────── */}
      <section style={{ padding: "var(--s8) 0 var(--s4)" }}>
        <h2
          style={{
            fontSize: "22px",
            fontWeight: 700,
            letterSpacing: "-0.02em",
            marginBottom: "var(--s5)",
          }}
        >
          Architecture principles
        </h2>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))",
            gap: "var(--s4)",
          }}
        >
          {[
            {
              title: "Rules are data, not code",
              body: "All 83 detection rules are YAML definitions. The engine interprets them. Adding a rule never requires changing engine code.",
            },
            {
              title: "No LLMs in v1",
              body: "Every detection is deterministic — regex, schema validation, AST analysis, CVE lookup. LLM classification is deferred to v1.1.",
            },
            {
              title: "Collect everything, judge later",
              body: "Crawlers store all raw metadata. Analysis is a separate pass. We never discard data because we don't have a rule for it yet.",
            },
            {
              title: "History by default",
              body: "Every scan result is immutable. Scores change over time. The score_history table tracks every change. Trends are first-class.",
            },
            {
              title: "Never invoke tools",
              body: "We only call initialize and tools/list. Dynamic invocation is a separate, gated capability requiring explicit server-author opt-in.",
            },
            {
              title: "Evidence required",
              body: "Every finding must include rule_id, evidence (what triggered it), and remediation (how to fix it). Findings without evidence are useless.",
            },
          ].map((p) => (
            <div key={p.title} className="card-sm">
              <div
                style={{
                  fontSize: "13px",
                  fontWeight: 700,
                  color: "var(--text)",
                  marginBottom: "var(--s2)",
                  display: "flex",
                  alignItems: "center",
                  gap: "var(--s2)",
                }}
              >
                <span
                  style={{
                    width: 6,
                    height: 6,
                    background: "var(--accent)",
                    borderRadius: "50%",
                    flexShrink: 0,
                    display: "inline-block",
                  }}
                />
                {p.title}
              </div>
              <p style={{ fontSize: "13px", color: "var(--text-3)", lineHeight: 1.6 }}>
                {p.body}
              </p>
            </div>
          ))}
        </div>
      </section>
    </>
  );
}
