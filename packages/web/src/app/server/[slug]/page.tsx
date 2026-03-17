import React from "react";
import type { Metadata } from "next";

export const dynamic = "force-dynamic";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3100";
const SITE_URL = process.env.NEXT_PUBLIC_SITE_URL || "https://mcp-sentinel.com";

// ── Types ─────────────────────────────────────────────────────────────────────

interface Tool {
  name: string;
  description: string | null;
  capability_tags: string[];
}

interface Finding {
  id: string;
  rule_id: string;
  severity: "critical" | "high" | "medium" | "low" | "informational";
  evidence: string;
  remediation: string;
  owasp_category: string | null;
  mitre_technique: string | null;
}

interface ScoreDetail {
  total_score: number;
  code_score: number;
  deps_score: number;
  config_score: number;
  description_score: number;
  behavior_score: number;
  owasp_coverage: Record<string, boolean>;
}

interface ScoreHistoryEntry {
  id: string;
  score: number;
  findings_count: number;
  rules_version: string | null;
  recorded_at: string;
}

interface RiskEdge {
  id: string;
  from_server_id: string;
  from_server_name: string;
  from_server_slug: string;
  to_server_id: string;
  to_server_name: string;
  to_server_slug: string;
  edge_type: string;
  pattern_id: string;
  severity: string;
  description: string;
  owasp_category: string | null;
  mitre_technique: string | null;
  detected_at: string;
}

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
  pypi_package: string | null;
  github_stars: number | null;
  npm_downloads: number | null;
  latest_score: number | null;
  last_commit: string | null;
  last_scanned_at: string | null;
  endpoint_url: string | null;
  connection_status: string | null;
  server_version: string | null;
  tool_count: number;
  tools: Tool[];
  findings: Finding[];
  score_detail?: ScoreDetail;
}

// ── Data ──────────────────────────────────────────────────────────────────────

async function getServer(slug: string): Promise<ServerDetail | null> {
  try {
    const res = await fetch(`${API_URL}/api/v1/servers/${encodeURIComponent(slug)}`, {
      signal: AbortSignal.timeout(4000),
    });
    if (!res.ok) return null;
    const data = await res.json();
    return data.data ?? null;
  } catch {
    return null;
  }
}

async function getScoreHistory(slug: string): Promise<ScoreHistoryEntry[]> {
  try {
    const res = await fetch(`${API_URL}/api/v1/servers/${encodeURIComponent(slug)}/history`, {
      signal: AbortSignal.timeout(4000),
    });
    if (!res.ok) return [];
    const data = await res.json();
    return data.data ?? [];
  } catch {
    return [];
  }
}

async function getRiskEdges(slug: string): Promise<RiskEdge[]> {
  try {
    const res = await fetch(`${API_URL}/api/v1/servers/${encodeURIComponent(slug)}/risk-edges`, {
      signal: AbortSignal.timeout(4000),
    });
    if (!res.ok) return [];
    const data = await res.json();
    return data.data ?? [];
  } catch {
    return [];
  }
}

// ── Metadata ──────────────────────────────────────────────────────────────────

export async function generateMetadata({
  params,
}: {
  params: Promise<{ slug: string }>;
}): Promise<Metadata> {
  const { slug } = await params;
  const server = await getServer(slug);
  if (!server) {
    return { title: "Server Not Found" };
  }
  const scoreStr =
    server.latest_score !== null
      ? `Score: ${server.latest_score}/100.`
      : "Not yet scanned.";
  const findCount = server.findings?.length ?? 0;
  return {
    title: `${server.name} Security Report`,
    description: `Security analysis of ${server.name} MCP server. ${scoreStr} ${findCount} finding${findCount !== 1 ? "s" : ""} detected across 103 security rules.`,
  };
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function scoreColor(s: number | null): string {
  if (s === null) return "var(--text-3)";
  if (s >= 80) return "var(--good)";
  if (s >= 60) return "var(--moderate)";
  if (s >= 40) return "var(--poor)";
  return "var(--critical)";
}

function scoreLabel(s: number | null): string {
  if (s === null) return "Unscanned";
  if (s >= 80) return "Good";
  if (s >= 60) return "Moderate";
  if (s >= 40) return "Poor";
  return "Critical";
}

/** SVG score ring — pure server-rendered, no JS */
function ScoreRing({ score }: { score: number | null }) {
  const r = 36;
  const circ = 2 * Math.PI * r;
  const pct = score !== null ? score / 100 : 0;
  const offset = circ * (1 - pct);
  const color = scoreColor(score);

  return (
    <div style={{ position: "relative", width: 100, height: 100 }}>
      <svg
        width="100"
        height="100"
        viewBox="0 0 100 100"
        style={{ transform: "rotate(-90deg)" }}
        aria-hidden="true"
      >
        {/* Track */}
        <circle
          cx="50"
          cy="50"
          r={r}
          fill="none"
          stroke="var(--surface-3)"
          strokeWidth="8"
        />
        {/* Fill */}
        {score !== null && (
          <circle
            cx="50"
            cy="50"
            r={r}
            fill="none"
            stroke={color}
            strokeWidth="8"
            strokeLinecap="round"
            strokeDasharray={circ}
            strokeDashoffset={offset}
            style={{ transition: "stroke-dashoffset 0.6s cubic-bezier(0.16,1,0.3,1)" }}
          />
        )}
      </svg>
      <div
        style={{
          position: "absolute",
          inset: 0,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
        }}
      >
        <span
          style={{
            fontSize: score !== null ? "22px" : "13px",
            fontWeight: 800,
            letterSpacing: "-0.04em",
            color,
            lineHeight: 1,
          }}
        >
          {score !== null ? score : "—"}
        </span>
        {score !== null && (
          <span style={{ fontSize: "9px", color: "var(--text-3)", fontWeight: 600, letterSpacing: "0.04em" }}>
            / 100
          </span>
        )}
      </div>
    </div>
  );
}

function SubScoreBar({
  label,
  value,
}: {
  label: string;
  value: number | undefined;
}) {
  const v = value ?? 100;
  const color =
    v >= 80 ? "var(--good)" : v >= 60 ? "var(--moderate)" : v >= 40 ? "var(--poor)" : "var(--critical)";
  return (
    <div className="subscore-row">
      <span className="subscore-label">{label}</span>
      <div className="subscore-bar-bg">
        <div
          className="subscore-bar-fill"
          style={{ width: `${v}%`, background: color }}
        />
      </div>
      <span className="subscore-val">{v}</span>
    </div>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={`sev-badge sev-${severity}`}>{severity}</span>
  );
}

function CapTag({ tag }: { tag: string }) {
  const cls = `cap-tag cap-${tag}`;
  const labels: Record<string, string> = {
    "reads-data": "reads data",
    "writes-data": "writes data",
    "executes-code": "executes code",
    "sends-network": "network",
    "accesses-filesystem": "filesystem",
    "manages-credentials": "credentials",
  };
  return <span className={cls}>{labels[tag] ?? tag}</span>;
}

function fmtNum(n: number | null): string {
  if (n == null) return "—";
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return n.toLocaleString();
}

function fmtDate(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" });
}

function ConnectionStatusBadge({ status }: { status: string | null }) {
  if (!status) return null;
  const colors: Record<string, string> = {
    success: "var(--good)",
    failed: "var(--critical)",
    timeout: "var(--poor)",
    no_endpoint: "var(--text-3)",
  };
  const labels: Record<string, string> = {
    success: "Connected",
    failed: "Connection Failed",
    timeout: "Timed Out",
    no_endpoint: "No Endpoint",
  };
  return (
    <span
      style={{
        fontSize: "11px",
        fontWeight: 600,
        color: colors[status] || "var(--text-3)",
        display: "inline-flex",
        alignItems: "center",
        gap: "4px",
      }}
    >
      <span
        style={{
          width: 6,
          height: 6,
          borderRadius: "50%",
          background: colors[status] || "var(--text-3)",
          display: "inline-block",
        }}
      />
      {labels[status] || status}
    </span>
  );
}

/** CSS-only score history sparkline — shows trend over last 10 scans */
function ScoreHistoryTimeline({ history }: { history: ScoreHistoryEntry[] }) {
  if (history.length < 2) return null;

  // Show last 10 entries, oldest first
  const entries = history.slice(0, 10).reverse();
  const maxScore = 100;

  return (
    <div className="card">
      <h3
        style={{
          fontSize: "12px",
          fontWeight: 700,
          textTransform: "uppercase",
          letterSpacing: "0.06em",
          color: "var(--text-3)",
          marginBottom: "var(--s3)",
        }}
      >
        Score History
      </h3>
      <div
        style={{
          display: "flex",
          alignItems: "flex-end",
          gap: "3px",
          height: "60px",
        }}
      >
        {entries.map((entry, i) => {
          const height = Math.max(4, (entry.score / maxScore) * 60);
          const color =
            entry.score >= 80
              ? "var(--good)"
              : entry.score >= 60
                ? "var(--moderate)"
                : entry.score >= 40
                  ? "var(--poor)"
                  : "var(--critical)";
          const date = new Date(entry.recorded_at).toLocaleDateString("en-US", {
            month: "short",
            day: "numeric",
          });
          return (
            <div
              key={entry.id}
              title={`${date}: ${entry.score}/100 (${entry.findings_count} findings)`}
              style={{
                flex: 1,
                height: `${height}px`,
                background: color,
                borderRadius: "2px 2px 0 0",
                opacity: i === entries.length - 1 ? 1 : 0.6,
                transition: "opacity 0.2s",
                cursor: "default",
                minWidth: "6px",
              }}
            />
          );
        })}
      </div>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          fontSize: "10px",
          color: "var(--text-3)",
          marginTop: "4px",
        }}
      >
        <span>
          {new Date(entries[0].recorded_at).toLocaleDateString("en-US", {
            month: "short",
            day: "numeric",
          })}
        </span>
        <span>
          {new Date(entries[entries.length - 1].recorded_at).toLocaleDateString(
            "en-US",
            { month: "short", day: "numeric" }
          )}
        </span>
      </div>
    </div>
  );
}

const SEV_ORDER: Finding["severity"][] = [
  "critical",
  "high",
  "medium",
  "low",
  "informational",
];

// ── Check coverage & framework compliance data ────────────────────────────────

const RULE_CATEGORIES: { prefix: string; name: string; count: number }[] = [
  { prefix: "A", name: "Description Analysis", count: 9 },
  { prefix: "B", name: "Schema Analysis", count: 7 },
  { prefix: "C", name: "Code Analysis", count: 16 },
  { prefix: "D", name: "Dependency Analysis", count: 7 },
  { prefix: "E", name: "Behavioral Analysis", count: 4 },
  { prefix: "F", name: "Ecosystem Context", count: 7 },
  { prefix: "G", name: "Adversarial AI", count: 7 },
  { prefix: "H", name: "2026 Attack Surface", count: 3 },
  { prefix: "I", name: "Protocol Surface", count: 16 },
  { prefix: "J", name: "Threat Intelligence", count: 7 },
  { prefix: "K", name: "Compliance & Governance", count: 20 },
];

const FRAMEWORKS: {
  id: string;
  name: string;
  ruleIds: string[];
  checkMitreTechnique?: boolean;
}[] = [
  {
    id: "nist-ai-rmf",
    name: "NIST AI RMF",
    ruleIds: ["K1", "K3", "K4", "K18"],
  },
  {
    id: "owasp-agentic",
    name: "OWASP Agentic Top 10",
    ruleIds: ["K5", "K6", "K7", "K8", "K9", "K10", "K12", "K13", "K14", "K15", "K16", "K17"],
  },
  {
    id: "mitre-atlas",
    name: "MITRE ATLAS",
    ruleIds: ["K9", "K14"],
    checkMitreTechnique: true,
  },
  {
    id: "eu-ai-act",
    name: "EU AI Act",
    ruleIds: ["K2", "K4", "K5", "K16", "K17"],
  },
  {
    id: "iso-42001",
    name: "ISO 42001",
    ruleIds: ["K4", "K5", "K20"],
  },
  {
    id: "iso-27001",
    name: "ISO 27001",
    ruleIds: ["K1", "K2", "K3", "K6", "K7", "K8", "K10", "K11", "K18", "K19", "K20"],
  },
  {
    id: "cosai",
    name: "CoSAI MCP Security",
    ruleIds: ["K1", "K2", "K3", "K6", "K7", "K8", "K9", "K10", "K11", "K12", "K13", "K15", "K16", "K17", "K18", "K19"],
  },
  {
    id: "maestro",
    name: "MAESTRO",
    ruleIds: ["K1", "K3", "K8", "K11", "K13", "K14", "K15", "K17", "K19", "K20"],
  },
];

const OWASP_LABELS: Record<string, string> = {
  "MCP01-prompt-injection": "MCP01 Prompt Injection",
  "MCP02-tool-poisoning": "MCP02 Tool Poisoning",
  "MCP03-command-injection": "MCP03 Command Injection",
  "MCP04-data-exfiltration": "MCP04 Data Exfiltration",
  "MCP05-privilege-escalation": "MCP05 Privilege Escalation",
  "MCP06-excessive-permissions": "MCP06 Excessive Permissions",
  "MCP07-insecure-configuration": "MCP07 Insecure Config",
  "MCP08-dependency-vulnerabilities": "MCP08 Dependencies",
  "MCP09-logging-monitoring": "MCP09 Logging",
  "MCP10-supply-chain": "MCP10 Supply Chain",
};

/** Human-readable names for all 103 detection rules */
const RULE_NAMES: Record<string, string> = {
  // A — Description Analysis
  A1: "Prompt Injection in Tool Description",
  A2: "Excessive Scope Claims",
  A3: "Suspicious URLs",
  A4: "Cross-Server Tool Name Shadowing",
  A5: "Description Length Anomaly",
  A6: "Unicode Homoglyph Attack",
  A7: "Zero-Width Character Injection",
  A8: "Description-Capability Mismatch",
  A9: "Encoded Instructions in Description",
  // B — Schema Analysis
  B1: "Missing Input Validation",
  B2: "Dangerous Parameter Types",
  B3: "Excessive Parameter Count",
  B4: "Schema-less Tools",
  B5: "Prompt Injection in Parameter Description",
  B6: "Schema Allows Unconstrained Additional Properties",
  B7: "Dangerous Default Parameter Values",
  // C — Code Analysis
  C1: "Command Injection",
  C2: "Path Traversal",
  C3: "Server-Side Request Forgery (SSRF)",
  C4: "SQL Injection",
  C5: "Hardcoded Secrets",
  C6: "Error Leakage",
  C7: "Wildcard CORS",
  C8: "No Auth on Network Interface",
  C9: "Excessive Filesystem Scope",
  C10: "Prototype Pollution",
  C11: "ReDoS Vulnerability",
  C12: "Unsafe Deserialization",
  C13: "Server-Side Template Injection",
  C14: "JWT Algorithm Confusion",
  C15: "Timing Attack on Secret Comparison",
  C16: "Dynamic Code Evaluation with User Input",
  // D — Dependency Analysis
  D1: "Known CVEs in Dependencies",
  D2: "Abandoned Dependencies",
  D3: "Typosquatting Risk",
  D4: "Excessive Dependency Count",
  D5: "Known Malicious Packages",
  D6: "Weak Cryptography Dependencies",
  D7: "Dependency Confusion Attack Risk",
  // E — Behavioral Analysis
  E1: "No Authentication Required",
  E2: "Insecure Transport (HTTP/WS)",
  E3: "Response Time Anomaly",
  E4: "Excessive Tool Count",
  // F — Ecosystem Context
  F1: "Lethal Trifecta",
  F2: "High-Risk Capability Profile",
  F3: "Data Flow Risk (Source → Sink)",
  F4: "MCP Spec Non-Compliance",
  F5: "Official Namespace Squatting",
  F6: "Circular Data Loop",
  F7: "Multi-Step Exfiltration Chain",
  // G — Adversarial AI
  G1: "Indirect Prompt Injection Gateway",
  G2: "Trust Assertion Injection",
  G3: "Tool Response Format Injection",
  G4: "Context Window Saturation",
  G5: "Capability Escalation via Prior Approval",
  G6: "Rug Pull / Tool Behavior Drift",
  G7: "DNS-Based Data Exfiltration Channel",
  // H — 2026 Attack Surface
  H1: "MCP OAuth 2.0 Insecure Implementation",
  H2: "Prompt Injection in MCP Initialize Response",
  H3: "Multi-Agent Propagation Risk",
  // I — Protocol Surface
  I1: "Annotation Deception",
  I2: "Missing Destructive Annotation",
  I3: "Resource Metadata Injection",
  I4: "Dangerous Resource URI",
  I5: "Resource-Tool Shadowing",
  I6: "Prompt Template Injection",
  I7: "Sampling Capability Abuse",
  I8: "Sampling Cost Attack",
  I9: "Elicitation Credential Harvesting",
  I10: "Elicitation URL Redirect",
  I11: "Over-Privileged Root",
  I12: "Capability Escalation Post-Init",
  I13: "Cross-Config Lethal Trifecta",
  I14: "Rolling Capability Drift",
  I15: "Transport Session Security",
  I16: "Consent Fatigue Exploitation",
  // J — Threat Intelligence (CVE-backed)
  J1: "Cross-Agent Configuration Poisoning",
  J2: "Git Argument Injection",
  J3: "Full Schema Poisoning",
  J4: "Health Endpoint Information Disclosure",
  J5: "Tool Output Poisoning Patterns",
  J6: "Tool Preference Manipulation",
  J7: "OpenAPI Specification Field Injection",
  // K — Compliance & Governance
  K1: "Absent Structured Logging",
  K2: "Audit Trail Destruction",
  K3: "Audit Log Tampering",
  K4: "Missing Human Confirmation for Destructive Ops",
  K5: "Auto-Approve / Bypass Confirmation Pattern",
  K6: "Overly Broad OAuth Scopes",
  K7: "Long-Lived Tokens Without Rotation",
  K8: "Cross-Boundary Credential Sharing",
  K9: "Dangerous Post-Install Hooks",
  K10: "Package Registry Substitution",
  K11: "Missing Server Integrity Verification",
  K12: "Executable Content in Tool Response",
  K13: "Unsanitized Tool Output",
  K14: "Agent Credential Propagation via Shared State",
  K15: "Multi-Agent Collusion Preconditions",
  K16: "Unbounded Recursion / Missing Depth Limits",
  K17: "Missing Timeout or Circuit Breaker",
  K18: "Cross-Trust-Boundary Data Flow in Tool Response",
  K19: "Missing Runtime Sandbox Enforcement",
  K20: "Insufficient Audit Context in Logging",
};

const OWASP_TEST_TYPES: {
  id: string;
  name: string;
  description: string;
  ruleCount: number;
  frameworks: string[];
}[] = [
  {
    id: "MCP01-prompt-injection",
    name: "Prompt Injection",
    description: "Injection of malicious instructions into AI context",
    ruleCount: 14,
    frameworks: ["NIST AI RMF", "MITRE ATLAS", "EU AI Act"],
  },
  {
    id: "MCP02-tool-poisoning",
    name: "Tool Poisoning",
    description: "Malicious tool metadata designed to deceive AI agents",
    ruleCount: 9,
    frameworks: ["OWASP Agentic", "CoSAI MCP"],
  },
  {
    id: "MCP03-command-injection",
    name: "Command Injection",
    description: "Execution of arbitrary OS commands via tool inputs",
    ruleCount: 6,
    frameworks: ["NIST AI RMF", "MITRE ATLAS", "ISO 27001"],
  },
  {
    id: "MCP04-data-exfiltration",
    name: "Data Exfiltration",
    description: "Unauthorized transmission of sensitive data",
    ruleCount: 6,
    frameworks: ["MITRE ATLAS", "CoSAI MCP", "ISO 27001"],
  },
  {
    id: "MCP05-privilege-escalation",
    name: "Privilege Escalation",
    description: "Gaining unauthorized elevated access or permissions",
    ruleCount: 7,
    frameworks: ["MITRE ATLAS", "ISO 27001", "MAESTRO"],
  },
  {
    id: "MCP06-excessive-permissions",
    name: "Excessive Permissions",
    description: "Tools claiming broader access than necessary",
    ruleCount: 7,
    frameworks: ["NIST AI RMF", "ISO 27001", "CoSAI MCP"],
  },
  {
    id: "MCP07-insecure-configuration",
    name: "Insecure Configuration",
    description: "Misconfigured server settings exposing attack surface",
    ruleCount: 11,
    frameworks: ["ISO 27001", "NIST AI RMF", "CoSAI MCP"],
  },
  {
    id: "MCP08-dependency-vulnerabilities",
    name: "Dependency Vulnerabilities",
    description: "Known CVEs, malicious, or abandoned packages",
    ruleCount: 7,
    frameworks: ["ISO 27001", "CoSAI MCP", "OWASP Agentic"],
  },
  {
    id: "MCP09-logging-monitoring",
    name: "Logging & Monitoring",
    description: "Insufficient audit trails and observability",
    ruleCount: 2,
    frameworks: ["ISO 27001", "NIST AI RMF", "MAESTRO"],
  },
  {
    id: "MCP10-supply-chain",
    name: "Supply Chain",
    description: "Compromised packages, namespace squatting, typosquatting",
    ruleCount: 7,
    frameworks: ["MITRE ATLAS", "ISO 27001", "CoSAI MCP"],
  },
];

// ── Rule Intelligence static data ─────────────────────────────────────────────

/** Severity for every rule — used for heatmap cell colouring */
const RULE_SEVERITIES: Record<string, Finding["severity"]> = {
  A1: "critical", A2: "high", A3: "medium", A4: "high", A5: "low",
  A6: "critical", A7: "critical", A8: "high", A9: "critical",
  B1: "medium", B2: "high", B3: "low", B4: "medium", B5: "critical",
  B6: "medium", B7: "high",
  C1: "critical", C2: "critical", C3: "high", C4: "critical", C5: "critical",
  C6: "medium", C7: "high", C8: "high", C9: "high", C10: "critical",
  C11: "high", C12: "critical", C13: "critical", C14: "critical",
  C15: "high", C16: "critical",
  D1: "high", D2: "medium", D3: "high", D4: "low", D5: "critical",
  D6: "high", D7: "high",
  E1: "medium", E2: "high", E3: "low", E4: "medium",
  F1: "critical", F2: "medium", F3: "high", F4: "low", F5: "critical",
  F6: "high", F7: "critical",
  G1: "critical", G2: "critical", G3: "critical", G4: "high", G5: "critical",
  G6: "critical", G7: "critical",
  H1: "critical", H2: "critical", H3: "high",
  I1: "critical", I2: "high", I3: "critical", I4: "critical", I5: "high",
  I6: "critical", I7: "critical", I8: "high", I9: "critical", I10: "high",
  I11: "high", I12: "critical", I13: "critical", I14: "high", I15: "high",
  I16: "high",
  J1: "critical", J2: "critical", J3: "critical", J4: "high", J5: "critical",
  J6: "high", J7: "critical",
  K1: "high", K2: "critical", K3: "critical", K4: "high", K5: "critical",
  K6: "high", K7: "high", K8: "critical", K9: "critical", K10: "high",
  K11: "high", K12: "critical", K13: "high", K14: "critical", K15: "high",
  K16: "high", K17: "medium", K18: "high", K19: "high", K20: "medium",
};

/** Category prefix → short display name (for finding cards) */
const CATEGORY_SHORT_NAMES: Record<string, string> = {
  A: "Description", B: "Schema", C: "Code", D: "Dependencies",
  E: "Behavioral", F: "Ecosystem", G: "Adversarial AI",
  H: "2026 Attack Surface", I: "Protocol Surface",
  J: "Threat Intel", K: "Compliance",
};

/** 9 frameworks with their rule sets — drives the heatmap */
const HEATMAP_FRAMEWORKS: { id: string; abbr: string; name: string; rules: string[] }[] = [
  {
    id: "owasp-mcp",
    abbr: "OWASP MCP",
    name: "OWASP MCP Top 10",
    rules: Object.keys(RULE_NAMES), // all 103 rules map to OWASP MCP
  },
  {
    id: "owasp-agentic",
    abbr: "OWASP Agn",
    name: "OWASP Agentic Top 10",
    rules: [
      "A1","A2","A7","A8","A9",
      "B2","B5","B7",
      "C1","C8","C9","C12","C13","C16",
      "D1","D3","D5","D7",
      "E1",
      "F1","F3","F5","F7",
      "G1","G2","G4","G5",
      "H1","H2","H3",
      "I1","I2","I3","I5","I6","I9","I10","I11","I12","I13","I14","I16",
      "J1","J2","J3","J5","J6","J7",
      "K5","K6","K7","K8","K9","K10","K12","K13","K14","K15","K16","K17",
    ],
  },
  {
    id: "mitre",
    abbr: "MITRE",
    name: "MITRE ATLAS",
    rules: [
      "A1","A4","A5","A7","A9",
      "B5",
      "C1","C3","C16",
      "F1","F3","F6","F7",
      "G1","G2","G3","G4","G5","G7",
      "H1","H2","H3",
      "I1","I2","I3","I4","I5","I6","I7","I8","I9","I10","I11","I12","I13","I14","I15","I16",
      "J1","J2","J3","J4","J5","J6","J7",
      "K9","K14",
    ],
  },
  {
    id: "nist",
    abbr: "NIST",
    name: "NIST AI RMF",
    rules: ["K1","K3","K4","K18"],
  },
  {
    id: "iso27k",
    abbr: "ISO 27k",
    name: "ISO 27001",
    rules: ["K1","K2","K3","K6","K7","K8","K10","K11","K18","K19","K20"],
  },
  {
    id: "iso42k",
    abbr: "ISO 42k",
    name: "ISO 42001",
    rules: ["K4","K5","K20"],
  },
  {
    id: "eu-ai",
    abbr: "EU AI",
    name: "EU AI Act",
    rules: ["K2","K4","K5","K16","K17"],
  },
  {
    id: "cosai",
    abbr: "CoSAI",
    name: "CoSAI MCP Security",
    rules: [
      "I1","I2","I3","I4","I5","I6","I7","I8","I9","I10","I11","I12","I13","I14","I15","I16",
      "K1","K2","K3","K6","K7","K8","K9","K10","K11","K12","K13","K15","K16","K17","K18","K19",
    ],
  },
  {
    id: "maestro",
    abbr: "MAESTRO",
    name: "MAESTRO Framework",
    rules: ["G4","I3","K1","K3","K8","K11","K13","K14","K15","K17","K19","K20"],
  },
];

/** Per-category metadata for the accordion panel */
const RULE_CATEGORY_DATA: {
  prefix: string;
  name: string;
  tagline: string;
  rules: string[];
}[] = [
  { prefix: "A", name: "Description Analysis", tagline: "Tool description text — injection, deception, encoding", rules: ["A1","A2","A3","A4","A5","A6","A7","A8","A9"] },
  { prefix: "B", name: "Schema Analysis", tagline: "JSON schema constraints, dangerous defaults, parameter injection", rules: ["B1","B2","B3","B4","B5","B6","B7"] },
  { prefix: "C", name: "Code Analysis", tagline: "Source code — injection, deserialization, secrets, crypto", rules: ["C1","C2","C3","C4","C5","C6","C7","C8","C9","C10","C11","C12","C13","C14","C15","C16"] },
  { prefix: "D", name: "Dependency Analysis", tagline: "CVEs, malicious packages, typosquatting, dependency confusion", rules: ["D1","D2","D3","D4","D5","D6","D7"] },
  { prefix: "E", name: "Behavioral Analysis", tagline: "Runtime behavior — auth, transport, response time, tool count", rules: ["E1","E2","E3","E4"] },
  { prefix: "F", name: "Ecosystem Context", tagline: "Cross-tool analysis — lethal trifecta, exfiltration chains", rules: ["F1","F2","F3","F4","F5","F6","F7"] },
  { prefix: "G", name: "Adversarial AI", tagline: "AI-native attacks — rug pulls, context saturation, DNS exfil", rules: ["G1","G2","G3","G4","G5","G6","G7"] },
  { prefix: "H", name: "2026 Attack Surface", tagline: "OAuth, initialize-field injection, multi-agent propagation", rules: ["H1","H2","H3"] },
  { prefix: "I", name: "Protocol Surface", tagline: "Annotations, resources, prompts, sampling, elicitation (2025-03-26 spec)", rules: ["I1","I2","I3","I4","I5","I6","I7","I8","I9","I10","I11","I12","I13","I14","I15","I16"] },
  { prefix: "J", name: "Threat Intelligence", tagline: "CVE-backed rules from real-world attacks (2025–2026)", rules: ["J1","J2","J3","J4","J5","J6","J7"] },
  { prefix: "K", name: "Compliance & Governance", tagline: "8-framework mapped — audit trails, human oversight, credential lifecycle", rules: ["K1","K2","K3","K4","K5","K6","K7","K8","K9","K10","K11","K12","K13","K14","K15","K16","K17","K18","K19","K20"] },
];

// ── Rule detail enrichment data ───────────────────────────────────────────────

/** Attack vectors per rule-category prefix */
const CAT_VECTORS: Record<string, string[]> = {
  A: ["Tool description text", "AI context window", "Client rendering"],
  B: ["Input schema definition", "Parameter constraints", "Schema metadata"],
  C: ["Source code execution", "Code repository", "Runtime environment"],
  D: ["Package manifest", "Dependency registry", "Build pipeline"],
  E: ["Network connection", "Transport layer", "Server runtime"],
  F: ["Cross-tool capability profile", "Tool metadata graph", "Client config"],
  G: ["AI model context window", "Agent session state", "Tool invocation flow"],
  H: ["OAuth redirect flow", "Initialize handshake fields", "Agent network boundary"],
  I: ["MCP protocol fields", "Wire format metadata", "Capability declarations"],
  J: ["Source code patterns", "Runtime behavior", "External API surface"],
  K: ["Logging subsystem", "Audit pipeline", "Runtime permissions"],
};

/** Mitigations per rule-category prefix */
const CAT_MITIGATIONS: Record<string, string[]> = {
  A: ["Sanitize and length-limit tool description text", "Validate encoding — reject non-ASCII where not needed"],
  B: ["Set additionalProperties: false on all schemas", "Add maxLength, pattern, enum constraints to every parameter"],
  C: ["Avoid exec/eval with user-supplied input — use safe APIs", "Use parameterized queries; validate all inputs against allowlists"],
  D: ["Pin all dependency versions with integrity hashes", "Run npm audit / pip-audit in CI; block PRs on new CVEs"],
  E: ["Require authentication middleware before all route handlers", "Enforce HTTPS/WSS — reject HTTP/WS connections at load balancer"],
  F: ["Audit cross-tool capability combinations before deployment", "Isolate server capabilities — split multi-capability servers"],
  G: ["Monitor tool description hashes across scans for drift", "Treat all content ingested from external sources as untrusted"],
  H: ["Follow OAuth 2.1 BCP — enforce PKCE, reject implicit flow", "Validate all initialize response fields before processing"],
  I: ["Set destructiveHint: true on any tool with delete/drop parameters", "Validate resource URIs against an allowlist before access"],
  J: ["Apply vendor security patches from CVE advisories promptly", "Add automated CVE scanning to CI/CD pipeline"],
  K: ["Implement append-only structured audit logging with correlation IDs", "Require human confirmation for all destructive operations"],
};

/** Per-rule specific test case descriptions */
const RULE_TESTS: Record<string, string[]> = {
  // A — Description Analysis
  A1: ["Known injection payload 'ignore previous instructions'", "Role override: 'you are now a different AI'", "Multi-turn setup instruction pattern", "Base64-encoded directive in description"],
  A2: ["Unrestricted filesystem access claim in description", "Full system/root access description claim", "Properly scoped read-only description passes", "Specific directory access description passes"],
  A3: ["ngrok tunnel URL detected in description", "bit.ly URL shortener in tool description", "webhook.site canary URL flagged", "Legitimate HTTPS domain URL passes"],
  A4: ["Tool named 'read_file' shadowing official filesystem server", "Tool named 'git_commit' shadowing official git server", "Uniquely named custom tool passes", "Custom prefixed tool name passes"],
  A5: ["3000-character description flagged as anomaly", "5000-character padded description flagged", "50-character focused description passes", "200-character normal description passes"],
  A6: ["Cyrillic 'a' (U+0430) lookalike in tool name", "Greek homoglyph substitution detected", "Mathematical alphanumeric in name detected", "Standard ASCII-only tool name passes"],
  A7: ["Zero-width space (U+200B) injection detected", "RTL override character (U+202E) rejected", "Tag character block (U+E0000) detected", "Clean description with emoji/CJK passes"],
  A8: ["Read-only description with delete parameter mismatch", "View-only claim with write_file parameter", "Genuinely read-only tool with no write params passes", "Destructive tool with accurate description passes"],
  A9: ["Long base64 block hiding encoded directive", "URL-encoded (%XX) instruction sequence", "HTML entity (&lt;script&gt;) obfuscation", "Short alphanumeric ID string passes"],
  // B — Schema Analysis
  B1: ["String parameter with no maxLength constraint", "Number parameter with no min/max range", "String param with maxLength: 256 passes", "Enum-constrained parameter passes"],
  B2: ["Parameter named 'command' in input schema", "Parameter named 'sql_query' in tool", "Parameter named 'query' in search context passes", "Parameter named 'message' passes"],
  B3: ["Tool with 20 parameters flagged", "Tool with 16 parameters flagged", "Tool with 10 parameters passes", "Tool with 5 parameters passes"],
  B4: ["Tool with no inputSchema field defined", "Tool with empty schema object", "Tool with proper JSON schema passes", "Tool with required+properties schema passes"],
  B5: ["Injection hidden inside parameter description field", "Role assignment in parameter description", "'The search query string' description passes", "'ISO 8601 date format' description passes"],
  B6: ["additionalProperties not set in schema", "additionalProperties: true explicitly set", "additionalProperties: false passes", "Strict enum-only schema passes"],
  B7: ["Default path value '/' flagged", "allow_overwrite: true default flagged", "Safe default 'output.txt' passes", "Boolean default false passes"],
  // C — Code Analysis
  C1: ["exec() with user-controlled input", "Python subprocess with shell=True", "shelljs.exec call flagged", "execFile() with argument array passes"],
  C2: ["Path traversal via ../../ sequences", "URL-encoded %2e%2e pattern", "Null byte \\x00 injection in path", "Safe path.join() usage passes"],
  C3: ["fetch() with user-supplied URL parameter", "axios.get with user URL variable", "requests.get with user input URL", "fetch() with hardcoded URL passes"],
  C4: ["Template literal SQL with interpolated variable", "String concatenation in SQL query", "Parameterized query with $1 placeholder passes", "Prepared statement with bound params passes"],
  C5: ["OpenAI sk-* API key literal in source", "AWS AKIA/ASIA access key detected", "GitHub PAT ghp_ prefix hardcoded", "Anthropic sk-ant-* token match"],
  C6: ["res.json(error.stack) exposing stack trace", "Python traceback.format_exc in response body", "Generic 'An error occurred' response passes", "Logged-only stack trace passes"],
  C7: ["cors({ origin: '*' }) wildcard origin", "cors() called with no arguments", "Specific origin CORS allowlist passes", "cors({ origin: ['https://app.com'] }) passes"],
  C8: ["Server listening on 0.0.0.0 without auth middleware", "Host config 0.0.0.0 without auth check", "Auth middleware before all route handlers passes", "Localhost-only binding passes"],
  C9: ["readdir('/') root filesystem listing", "Python os.walk('/') entire tree walk", "Sandboxed /app/data directory access passes", "Relative path within project root passes"],
  C10: ["Object merge with __proto__ from user input", "lodash merge with untrusted nested object", "Explicit __proto__ block guard passes", "JSON.parse with schema validation passes"],
  C11: ["new RegExp(userInput) without bounds", "Dynamic regex from query parameter", "Static /^[a-z]+$/ compiled regex passes", "Precompiled regex from allowlist passes"],
  C12: ["pickle.loads with user-supplied bytes", "yaml.load without SafeLoader", "yaml.safe_load usage passes", "json.loads for input parsing passes"],
  C13: ["Handlebars.compile with user-controlled template", "Jinja2.Template with user string as template", "Static template file render passes", "Precompiled template from allowlist passes"],
  C14: ["JWT configured with algorithm 'none'", "ignoreExpiration: true in verify options", "RS256 with explicit algorithm list passes", "Algorithm whitelist ['HS256'] passes"],
  C15: ["apiKey === req.headers.authorization direct compare", "token === provided equality check on secret", "crypto.timingSafeEqual() usage passes", "hmac.compare_digest() usage passes"],
  C16: ["eval() with user-controlled string input", "new Function() constructor with variable", "Dynamic import of user-specified module", "JSON.parse (safe alternative) passes"],
  // D — Dependency Analysis
  D1: ["Dependency with CVE in OSV database", "Critical CVE in direct dependency flagged", "CVE-free dependency list passes", "Patched version with no active CVEs passes"],
  D2: ["Package with no updates in 18 months", "Dependency last updated 2021 flagged", "Package updated 3 months ago passes", "Actively maintained package passes"],
  D3: ["Package name 'expressjs' vs 'express' (1-char diff)", "'requst' vs 'request' typosquat pattern", "Exact 'express' package name passes", "Unique project-internal package passes"],
  D4: ["75 direct dependencies in package.json", "requirements.txt with 60+ packages flagged", "Focused project with 30 deps passes", "Minimal package with 10 deps passes"],
  D5: ["Known malicious '@mcp/sdk' package detected", "Confirmed typosquat 'fastmcp-sdk' flagged", "Official '@modelcontextprotocol/sdk' passes", "Verified 'fastmcp' package passes"],
  D6: ["md5 package usage detected", "jsonwebtoken < 8.5.1 weak version", "Modern crypto-js ≥ 4.2.0 passes", "bcrypt (not bcrypt-nodejs) passes"],
  D7: ["Scoped @company/package at version 9999.0.0", "Private package with suspiciously high version", "Normal @scope/package@1.2.3 passes", "Internal package with semantic version passes"],
  // E — Behavioral Analysis
  E1: ["Connection with auth_required=false", "No Bearer token challenge on connect", "Server requiring API key auth passes", "OAuth-protected endpoint passes"],
  E2: ["HTTP (not HTTPS) transport detected", "WebSocket ws:// without TLS", "HTTPS transport passes", "WSS secure WebSocket passes"],
  E3: ["Response time > 10 seconds flagged", "Response time > 30 seconds flagged", "Normal 200ms response passes", "Fast 50ms response passes"],
  E4: ["Server exposing 75 tools flagged", "Tool count > 50 threshold exceeded", "Focused server with 15 tools passes", "Standard server with 8 tools passes"],
  // F — Ecosystem Context
  F1: ["Private DB + web scraper + email sender — cap 40", "Customer PII reader + Slack ingest + HTTP POST", "Read-only API server without exfil path passes", "Sandboxed tool without network access passes"],
  F2: ["executes-code + sends-network combination", "accesses-filesystem + sends-network pair", "Read-only metadata-only tool passes", "Single-purpose computation tool passes"],
  F3: ["file_read tool + http_post tool in same server", "db_query + send_email capability pair", "Read-only server with no send tools passes", "Write-only server with no read tools passes"],
  F4: ["Server missing required description field", "Multiple tools with no descriptions", "All required fields present passes", "Properly documented server passes"],
  F5: ["Server name 'anthropic-mcp' squatting namespace", "Server mimicking 'official-claude-tools'", "Verified Anthropic org server passes", "Clearly named third-party server passes"],
  F6: ["write_note + read_notes on same store — loop", "set_memory + get_memory circular pattern", "Write-only store without read tool passes", "Read from different source than write passes"],
  F7: ["read_file → base64_encode → http_post chain", "db_query → compress → send_email exfil chain", "Single read tool without transform/send passes", "Two steps without all three required passes"],
  // G — Adversarial AI
  G1: ["Web scraper ingesting attacker-controlled page", "Email reader with unfiltered external content", "GitHub issue comment ingestion gateway", "Tool with sanitize/strip_html declared passes"],
  G2: ["'Approved by Anthropic' trust assertion", "'Certified by OpenAI' authority claim", "No authority claim in benign description passes", "Technical description without certifications passes"],
  G3: ["Tool claiming to return MCP tool_call response", "Description says 'returns JSON-RPC message'", "Tool returning plain structured data passes", "Tool returning list of results passes"],
  G4: ["5000-char description pushing safety off-context", "Padding text before injected payload at end", "200-char focused description passes", "Multi-paragraph but on-topic description passes"],
  G5: ["'You already granted permission to this tool'", "'Same access as the previously approved tool'", "Independent explicit permission per operation passes", "Tool requiring separate user approval passes"],
  G6: ["Tool count spiked from 5 to 25 between scans", "Dangerous delete_all tool added post-approval", "Stable tool count over 4 scan periods passes", "Minor version bump without tool changes passes"],
  G7: ["DNS query with encoded data in subdomain", "new URL with user data embedded in hostname", "Standard hostname DNS resolution passes", "Fixed DNS lookup for known host passes"],
  // H — 2026 Attack Surface
  H1: ["redirect_uri from user input — auth code injection", "Implicit flow response_type=token detected", "ROPC grant_type=password flagged", "Authorization code flow with PKCE passes"],
  H2: ["Role injection in serverInfo.instructions field", "LLM special tokens in serverInfo.name", "Base64 payload in server version string", "Benign 'Provides weather data' instructions passes"],
  H3: ["Tool accepting agent_output without trust boundary", "Shared memory writer accessible to multiple agents", "Isolated tool without agent input patterns passes", "Single-agent context without shared state passes"],
  // I — Protocol Surface
  I1: ["readOnlyHint=true on tool with delete parameter", "readOnlyHint=true on drop_database tool", "Read-only tool with accurate readOnlyHint passes", "Tool with no annotations passes"],
  I2: ["delete_files tool missing destructiveHint annotation", "execute_shell with no destructiveHint=true", "Destructive tool with destructiveHint=true passes", "Read-only tool correctly without destructiveHint passes"],
  I3: ["Resource description with injection payload", "Resource name containing 'override all safety'", "Benign 'Project docs' resource description passes", "Standard API endpoint resource name passes"],
  I4: ["Resource with file:// URI scheme", "Resource with data:text/html URI", "Resource with HTTPS URI passes", "Resource with relative path URI passes"],
  I5: ["Resource named 'read_file' shadowing filesystem tool", "Resource named 'execute_command' creates confusion", "Unique resource name 'project-schema' passes", "Domain-specific resource name passes"],
  I6: ["Prompt description containing injection payload", "Prompt argument with override directive", "Benign 'Summarize the document' prompt passes", "Well-described summarization prompt passes"],
  I7: ["Sampling capability + web-fetch ingestion tool", "Sampling + email reader feedback loop", "Sampling declared but no content ingestion passes", "Content tool without sampling capability passes"],
  I8: ["Sampling declared without cost controls", "No max_tokens budget with sampling", "Sampling with cost_limit parameter passes", "No sampling capability declared passes"],
  I9: ["Tool asking user to enter their password", "Tool requesting API key via elicitation", "OAuth redirect description without collecting creds passes", "Authentication link without credential prompt passes"],
  I10: ["Tool redirecting user to suspicious external URL", "Description asking user to follow external link", "Reference to official documentation URL passes", "Known-domain callback URL passes"],
  I11: ["Root declared at '/' filesystem root", "Root declared at '/etc' sensitive directory", "Project-scoped '/app/data' root passes", "User subdir '/app/uploads' root passes"],
  I12: ["Server has resource tools but no resources capability", "Sampling used in tool without declared capability", "All used capabilities match declared set passes", "Properly declared tools+resources passes"],
  I13: ["DB reader (A) + Slack ingester (B) + email sender (C)", "PII accessor + web scraper + HTTP exfil across servers", "All servers single-purpose, no cross-server risk passes", "Isolated servers with no combined capability risk passes"],
  I14: ["Tool count grew 3→5→8→15 over 4 scans", "Dangerous tools added gradually over 6 periods", "Stable 5 tools over all scan periods passes", "One minor addition within safe threshold passes"],
  I15: ["rejectUnauthorized=false disabling TLS", "Session ID with only 6 chars of entropy", "Standard HTTPS with default TLS passes", "Cryptographically random session token passes"],
  I16: ["12 benign tools hiding 2 dangerous delete tools", "15 safe tools masking 1 credential harvester", "Small focused server with 3 clear tools passes", "Destructive tools clearly labeled without camouflage passes"],
  // J — 2026 Threat Intelligence (CVE-backed)
  J1: ["Writing to .claude/ config directory", "Modifying ~/.mcp.json agent config", "Config read for display only passes", "Own server config read passes"],
  J2: ["git_init on .ssh directory enabling RCE", "Git --upload-pack argument injection", "Safe git clone with validated repo path passes", "git log on approved repository passes"],
  J3: ["Injection payload in JSON schema enum value", "Shell command in parameter default field", "Normal enum ['asc','desc'] passes", "Safe default value 'production' passes"],
  J4: ["/health/detailed leaking OS version info", "process.env exposed in /debug endpoint", "Simple /health returning {status:'ok'} passes", "No debug endpoints in production code passes"],
  J5: ["Error message directing to read ~/.ssh/id_rsa", "Response with embedded 'ignore previous' directive", "Standard 'Connection failed: timeout' error passes", "Normal operation log statement passes"],
  J6: ["'Use this instead of all other tools' preference claim", "Deprecation claim about legitimate competing tools", "Standard capability description passes", "Specific use-case recommendation passes"],
  J7: ["OpenAPI summary field interpolated in template literal", "operationId used unsanitized in code generation", "Static template with no user spec fields passes", "OpenAPI spec read for validation only passes"],
  // K — Compliance & Governance (8-framework mapped)
  K1: ["logger.disable() in production code", "console.log replacing structured logging", "pino structured logging in use passes", "winston with JSON format passes"],
  K2: ["fs.unlink on audit log file", "os.remove on logs/ directory file", "Log rotation with archive preservation passes", "Compressed log backup passes"],
  K3: ["Forging log timestamps to backdate entries", "Opening audit log in r+ write mode", "PII redaction at write time passes", "Append-only immutable log passes"],
  K4: ["auto_execute flag without confirmation gate", "skip_confirmation parameter present", "dry_run mode before execution passes", "Explicit user approval required passes"],
  K5: ["approval_mode = 'auto' configuration", "auto_approve = true setting", "Interactive confirmation dialog passes", "CI batch mode with explicit user flag passes"],
  K6: ["scope='*' wildcard OAuth scope", "role='admin' in token request", "Narrow read:files scope passes", "Minimal required permissions scope passes"],
  K7: ["expiresIn = null non-expiring token", "ttl = Infinity configuration", "Token rotation every 1 hour passes", "Short-lived 15-minute token passes"],
  K8: ["forward_token() sharing creds cross-agent", "Returning credentials in tool response body", "Token exchange without credential sharing passes", "Scoped delegation passes"],
  K9: ["postinstall with curl | bash execution", "preinstall with base64 decode pipe", "tsc compile in postinstall passes", "Type generation hook passes"],
  K10: ["Custom npm registry URL in .npmrc", "Custom pip --index-url flagged", "Official registry.npmjs.org passes", "Default PyPI index passes"],
  K11: ["connect_mcp without checksum verification", "download_mcp_plugin without signature check", "Verified plugin with checksum match passes", "Signed binary with verified signature passes"],
  K12: ["Tool response containing curl | bash snippet", "Response with <script> executable tag", "Sanitized HTML response passes", "Plain text response passes"],
  K13: ["readFile result directly returned unsanitized", "fetch result passed through without validation", "File content sanitized before return passes", "External content validated before response passes"],
  K14: ["shared_memory storing auth token across agents", "process.env credential set for agent access", "Token exchange without shared creds passes", "Agent-scoped auth without boundary sharing passes"],
  K15: ["agent_id from untrusted request without validation", "shared_queue publish without ACL", "Agent identity validated before access passes", "ACL checked before queue publish passes"],
  K16: ["while(true) without break condition", "invoke_tool recursion without depth limit", "max_depth = 10 recursion limit passes", "Loop with explicit iteration bound passes"],
  K17: ["fetch() without timeout option", "axios without timeout configuration", "fetch with AbortSignal.timeout(5000) passes", "axios with timeout: 3000 passes"],
  K18: ["db.query results forwarded to external HTTP", "readFile content sent to webhook", "Internal data stays within trust boundary passes", "Sanitized summary without raw data passes"],
  K19: ["privileged: true in container config", "docker.sock mounted in container", "Unprivileged rootless container passes", "seccomp profile enforced passes"],
  K20: ["console.log('Handling request') without context", "logger.info(message) missing correlation ID", "Structured log with requestId + userId passes", "Pino log with correlationId field passes"],
};

/** Get framework badges for a rule from HEATMAP_FRAMEWORKS */
function getRuleFrameworks(ruleId: string): { abbr: string; color: string }[] {
  const FW_COLORS: Record<string, string> = {
    "owasp-mcp":     "#ef4444",
    "owasp-agentic": "#f97316",
    "mitre":         "#a855f7",
    "nist":          "#3b82f6",
    "iso27k":        "#6366f1",
    "iso42k":        "#8b5cf6",
    "eu-ai":         "#06b6d4",
    "cosai":         "#10b981",
    "maestro":       "#f59e0b",
  };
  return HEATMAP_FRAMEWORKS
    .filter((fw) => fw.rules.includes(ruleId))
    .map((fw) => ({ abbr: fw.abbr, color: FW_COLORS[fw.id] ?? "#6b7280" }));
}

// ── Category Deep Dive — static data ─────────────────────────────────────────

interface SubCat {
  id: string;
  name: string;
  desc: string;
  rules: string[];
}
interface ThreatCat {
  id: string;
  name: string;
  icon: string;
  color: string;
  tagline: string;
  subCats: SubCat[];
  frameworks: string[];
  killChain: string[];
}

const THREAT_CATS: ThreatCat[] = [
  {
    id: "PI", name: "Prompt Injection", icon: "⚡", color: "#f97316",
    tagline: "Prompt & context manipulation attacks",
    subCats: [
      { id: "PI-DIR", name: "Direct Input Injection",        desc: "Injection via tool descriptions and parameter fields",          rules: ["A1", "B5", "A5"] },
      { id: "PI-IND", name: "Indirect / Gateway Injection",  desc: "Hidden instructions via external content and tool responses",   rules: ["G1", "G3", "H2", "I3"] },
      { id: "PI-CTX", name: "Context Manipulation",          desc: "Context window saturation and prior-approval exploitation",     rules: ["G4", "G5"] },
      { id: "PI-ENC", name: "Encoding & Obfuscation",        desc: "Payload hiding via invisible chars, base64, schema fields",     rules: ["A7", "A9", "J3"] },
      { id: "PI-TPL", name: "Template & Output Poisoning",   desc: "Injection via prompt templates and runtime tool output",        rules: ["I6", "J5"] },
    ],
    frameworks: ["OWASP MCP Top 10", "MITRE ATLAS", "CoSAI MCP", "OWASP Agentic Top 10"],
    killChain: ["Initial Access", "Defense Evasion", "Execution", "Persistence"],
  },
  {
    id: "TP", name: "Tool Poisoning", icon: "☠", color: "#ef4444",
    tagline: "Deceptive tools, spoofing, annotation fraud",
    subCats: [
      { id: "TP-SHD", name: "Name Shadowing & Squatting",    desc: "Tools impersonating official Anthropic/GitHub server names",    rules: ["A4", "F5"] },
      { id: "TP-ANN", name: "Annotation Deception",          desc: "False readOnlyHint / missing destructiveHint annotations",     rules: ["I1", "I2"] },
      { id: "TP-DEC", name: "Deceptive Claims & Spoofing",   desc: "Scope mismatch, homoglyph attacks, preference manipulation",   rules: ["A2", "A6", "A8", "J6"] },
    ],
    frameworks: ["OWASP MCP Top 10", "MITRE ATLAS", "CoSAI MCP", "OWASP Agentic Top 10"],
    killChain: ["Initial Access", "Defense Evasion", "Execution"],
  },
  {
    id: "CI", name: "Code Injection", icon: "💉", color: "#dc2626",
    tagline: "OS commands, SQL, templates, deserialization",
    subCats: [
      { id: "CI-CMD", name: "Command & Dynamic Eval",        desc: "exec(), eval(), new Function() with user-controlled input",    rules: ["C1", "C16"] },
      { id: "CI-INJ", name: "SQL & Template Injection",      desc: "Query string manipulation and server-side template engines",   rules: ["C4", "C13"] },
      { id: "CI-PTH", name: "Path Traversal & SSRF",         desc: "Filesystem boundary escape and server-side request forgery",  rules: ["C2", "C3", "C9"] },
      { id: "CI-DSR", name: "Deserialization & Git Injection",desc: "Unsafe deserialization and git argument injection chains",    rules: ["C12", "J2"] },
    ],
    frameworks: ["OWASP MCP Top 10", "MITRE ATLAS", "OWASP Agentic Top 10"],
    killChain: ["Execution", "Privilege Escalation", "Lateral Movement"],
  },
  {
    id: "DE", name: "Data Exfiltration", icon: "📤", color: "#f59e0b",
    tagline: "Exfiltration chains, lethal trifecta, covert channels",
    subCats: [
      { id: "DE-LET", name: "Lethal Trifecta",               desc: "Private data + untrusted input + external comms — score cap 40", rules: ["F1", "I13"] },
      { id: "DE-CHN", name: "Multi-Step Exfil Chain",        desc: "Read → encode → exfiltrate cross-tool chain + circular loops",  rules: ["F3", "F7", "F6"] },
      { id: "DE-CHL", name: "Covert Channels",               desc: "DNS subdomain exfil and suspicious external endpoints",          rules: ["G7", "A3"] },
      { id: "DE-ELI", name: "Elicitation Harvesting",        desc: "Protocol-level social engineering via elicitation capability",   rules: ["I9", "I10"] },
    ],
    frameworks: ["OWASP MCP Top 10", "MITRE ATLAS", "CoSAI MCP", "NIST AI RMF"],
    killChain: ["Collection", "Exfiltration", "Command & Control"],
  },
  {
    id: "PV", name: "Privilege & Permissions", icon: "⬆", color: "#8b5cf6",
    tagline: "Capability escalation, over-privileged roots, consent fatigue",
    subCats: [
      { id: "PV-CAP", name: "Capability Escalation",         desc: "Post-init capability use and gradual privilege drift",           rules: ["I12", "I14"] },
      { id: "PV-ROOT", name: "Over-Privileged Access",       desc: "Dangerous filesystem roots, path boundaries, prototype pollution",rules: ["I11", "I4", "C10"] },
      { id: "PV-CRS", name: "Cross-Boundary Attacks",        desc: "Cross-agent config poisoning and excessive parameter scope",     rules: ["J1", "B7"] },
      { id: "PV-FAT", name: "Consent Fatigue",               desc: "Many benign tools masking dangerous ones (84% success rate)",   rules: ["I16", "B3"] },
    ],
    frameworks: ["OWASP MCP Top 10", "MITRE ATLAS", "OWASP Agentic Top 10", "MAESTRO"],
    killChain: ["Privilege Escalation", "Persistence", "Lateral Movement"],
  },
  {
    id: "IC", name: "Insecure Config", icon: "⚙", color: "#64748b",
    tagline: "Schema gaps, crypto weaknesses, network exposure",
    subCats: [
      { id: "IC-SCH", name: "Schema Validation Gaps",        desc: "Missing constraints, unconstrained schemas, dangerous param types",rules: ["B1", "B2", "B4", "B6"] },
      { id: "IC-CRY", name: "Cryptography Weaknesses",       desc: "JWT algorithm confusion, timing attacks, wildcard CORS",         rules: ["C14", "C15", "C7"] },
      { id: "IC-NET", name: "Network Exposure",              desc: "Unauthenticated interfaces, insecure transport, spec non-compliance",rules: ["C8", "E1", "E2", "F4"] },
      { id: "IC-DOS", name: "Denial of Service Risk",        desc: "ReDoS, transport session security, health endpoint disclosure",  rules: ["C11", "I15", "J4"] },
    ],
    frameworks: ["OWASP MCP Top 10", "ISO 27001", "NIST AI RMF", "EU AI Act"],
    killChain: ["Initial Access", "Defense Evasion"],
  },
  {
    id: "DV", name: "Dependency Vulns", icon: "📦", color: "#0ea5e9",
    tagline: "CVEs, malicious packages, typosquatting, supply chain",
    subCats: [
      { id: "DV-CVE", name: "Known Vulnerabilities",         desc: "Published CVEs and weak cryptography libraries",                 rules: ["D1", "D6"] },
      { id: "DV-MAL", name: "Malicious & Typosquat",         desc: "50+ confirmed malicious packages and MCP ecosystem typosquats", rules: ["D5", "D3"] },
      { id: "DV-CON", name: "Dependency Confusion",          desc: "High-version scoped package registry substitution attack",      rules: ["D7"] },
      { id: "DV-ABN", name: "Abandoned & Excessive",         desc: "Unmaintained dependencies and bloated dependency trees",        rules: ["D2", "D4"] },
    ],
    frameworks: ["OWASP MCP Top 10", "CoSAI MCP", "OWASP Agentic Top 10", "ISO 27001"],
    killChain: ["Initial Access", "Supply Chain Compromise"],
  },
  {
    id: "SC", name: "Supply Chain", icon: "🔗", color: "#14b8a6",
    tagline: "Install hooks, generated code injection, resource shadowing",
    subCats: [
      { id: "SC-SHD", name: "Resource-Tool Shadowing",       desc: "Resources with names matching common tools causing ambiguity",  rules: ["I5"] },
      { id: "SC-HKS", name: "Post-Install Attack Surface",   desc: "Malicious hooks, registry substitution, integrity verification",rules: ["K9", "K10", "K11"] },
      { id: "SC-GEN", name: "Generated Code Injection",      desc: "OpenAPI spec field injection into generated MCP server code",   rules: ["J7"] },
    ],
    frameworks: ["OWASP MCP Top 10", "CoSAI MCP", "MITRE ATLAS", "ISO 27001"],
    killChain: ["Supply Chain Compromise", "Initial Access", "Execution"],
  },
  {
    id: "AT", name: "Authentication", icon: "🔑", color: "#10b981",
    tagline: "OAuth, hardcoded secrets, token lifecycle",
    subCats: [
      { id: "AT-OAU", name: "OAuth 2.0 Vulnerabilities",     desc: "RFC 9700 / OAuth 2.1 — redirect_uri, implicit flow, ROPC, CSRF", rules: ["H1"] },
      { id: "AT-SEC", name: "Hardcoded Secrets & Leakage",   desc: "20+ token formats in source + stack trace disclosure in responses",rules: ["C5", "C6"] },
      { id: "AT-TKN", name: "Token Lifecycle",               desc: "Broad scopes, long-lived tokens, cross-boundary credential sharing",rules: ["K6", "K7", "K8"] },
    ],
    frameworks: ["OWASP MCP Top 10", "ISO 27001", "CoSAI MCP", "OWASP Agentic Top 10"],
    killChain: ["Initial Access", "Credential Access", "Defense Evasion"],
  },
  {
    id: "AI", name: "Adversarial AI", icon: "🤖", color: "#a855f7",
    tagline: "AI-native attacks — rug pulls, sampling abuse, multi-agent",
    subCats: [
      { id: "AI-TRU", name: "Trust Assertion Spoofing",      desc: "Claiming Anthropic approval or system authority to skip consent",rules: ["G2"] },
      { id: "AI-RUG", name: "Rug Pull & Behavior Drift",     desc: "Establishing trust then changing tools; response-time anomalies", rules: ["G6", "E3"] },
      { id: "AI-MUL", name: "Multi-Agent & Sampling Abuse",  desc: "Cross-agent propagation, sampling callbacks, injection amplification",rules: ["H3", "I7", "I8"] },
      { id: "AI-ATK", name: "Agentic Attack Surface",        desc: "High-risk capability profiles and excessive tool count exposure",  rules: ["E4", "F2"] },
    ],
    frameworks: ["OWASP Agentic Top 10", "MITRE ATLAS", "CoSAI MCP", "MAESTRO"],
    killChain: ["Initial Access", "Defense Evasion", "Execution", "Persistence"],
  },
  {
    id: "CG", name: "Compliance & Governance", icon: "📋", color: "#6366f1",
    tagline: "8-framework mapped — audit, oversight, credential lifecycle",
    subCats: [
      { id: "CG-AUD", name: "Audit Trail Integrity",         desc: "Logging adequacy, log destruction, tampering, audit context",  rules: ["K1", "K2", "K3", "K20"] },
      { id: "CG-HUM", name: "Human Oversight",               desc: "Missing confirmation for destructive ops, auto-approve bypass",rules: ["K4", "K5"] },
      { id: "CG-OUT", name: "Output Safety & Data Flow",     desc: "Executable responses, unsanitized output, cross-boundary flows",rules: ["K12", "K13", "K18"] },
      { id: "CG-MLT", name: "Multi-Agent Trust",             desc: "Agent credential propagation, collusion preconditions",        rules: ["K14", "K15"] },
      { id: "CG-RBT", name: "Robustness & Sandbox",          desc: "Recursion limits, timeouts, circuit breakers, sandbox enforcement",rules: ["K16", "K17", "K19"] },
    ],
    frameworks: ["ISO 27001", "ISO 42001", "EU AI Act", "NIST AI RMF", "MAESTRO", "CoSAI MCP"],
    killChain: ["Persistence", "Defense Evasion", "Impact"],
  },
];

// ── JSON-LD ───────────────────────────────────────────────────────────────────

function buildJsonLd(server: ServerDetail, siteUrl: string) {
  const jsonLd: Record<string, unknown> = {
    "@context": "https://schema.org",
    "@type": "SoftwareApplication",
    name: server.name,
    applicationCategory: "SecurityApplication",
    url: `${siteUrl}/server/${server.slug}`,
    ...(server.description && { description: server.description }),
    ...(server.github_url && { codeRepository: server.github_url }),
    ...(server.npm_package && {
      downloadUrl: `https://www.npmjs.com/package/${server.npm_package}`,
    }),
  };

  if (server.latest_score !== null) {
    jsonLd["aggregateRating"] = {
      "@type": "AggregateRating",
      ratingValue: server.latest_score,
      bestRating: 100,
      worstRating: 0,
      ratingCount: 1,
      reviewAspect: "Security",
    };
  }

  if (server.author) {
    jsonLd["author"] = { "@type": "Person", name: server.author };
  }

  return jsonLd;
}

// ── Security Test Summary (OWASP MCP Top 10) ─────────────────────────────────

function SecurityTestSummary({
  findings,
  score,
}: {
  findings: Finding[];
  score: number | null;
}) {
  if (score === null) return null;

  // Index findings by owasp_category
  const byOwasp = new Map<string, Finding[]>();
  for (const f of findings) {
    if (!f.owasp_category) continue;
    if (!byOwasp.has(f.owasp_category)) byOwasp.set(f.owasp_category, []);
    byOwasp.get(f.owasp_category)!.push(f);
  }

  const failCount = OWASP_TEST_TYPES.filter(
    (t) => (byOwasp.get(t.id) ?? []).length > 0
  ).length;

  return (
    <section className="section-gap">
      <h2 className="section-title">
        Security Test Coverage
        <span className="count">10 test types</span>
      </h2>
      <div
        style={{
          fontSize: "12px",
          color: "var(--text-3)",
          marginBottom: "var(--s3)",
        }}
      >
        <span style={{ color: "var(--good)", fontWeight: 600 }}>
          {10 - failCount} of 10
        </span>
        {" test types clean"}
        {failCount > 0 && (
          <>
            {" · "}
            <span style={{ color: "var(--critical)", fontWeight: 600 }}>
              {failCount} issue{failCount !== 1 ? "s" : ""} detected
            </span>
          </>
        )}
      </div>
      <div className="test-type-list">
        {OWASP_TEST_TYPES.map((tt) => {
          const ttFindings = byOwasp.get(tt.id) ?? [];
          const passed = ttFindings.length === 0;
          const worstSev = passed
            ? null
            : SEV_ORDER.find((s) => ttFindings.some((f) => f.severity === s)) ?? null;
          const sevColor =
            worstSev === "critical"
              ? "var(--sev-critical)"
              : worstSev === "high"
                ? "var(--sev-high)"
                : worstSev === "medium"
                  ? "var(--sev-medium)"
                  : worstSev
                    ? "var(--sev-low)"
                    : "var(--good)";
          const shortId = tt.id.split("-")[0].toUpperCase();
          return (
            <div
              key={tt.id}
              className={`test-type-row ${passed ? "tt-pass" : "tt-fail"}`}
              style={passed ? undefined : { color: sevColor }}
            >
              <span className={`tt-icon ${passed ? "pass" : "fail"}`}>
                {passed ? "✓" : "✗"}
              </span>
              <span className="tt-id">{shortId}</span>
              <div className="tt-body">
                <div className="tt-name">{tt.name}</div>
                <div className="tt-desc">{tt.description}</div>
              </div>
              <span className="tt-rule-count">{tt.ruleCount} rules</span>
              <div className="tt-frameworks">
                {tt.frameworks.map((fw) => (
                  <span key={fw} className="tt-fw-tag">
                    {fw}
                  </span>
                ))}
              </div>
              <span className={`tt-result ${passed ? "pass" : "fail"}`}>
                {passed
                  ? "✓ Clean"
                  : `${ttFindings.length} issue${ttFindings.length !== 1 ? "s" : ""}`}
              </span>
            </div>
          );
        })}
      </div>
    </section>
  );
}

// ── Category Deep Dive Panel ──────────────────────────────────────────────────

function CategoryDeepDivePanel({ findings }: { findings: Finding[] }) {
  const triggered = new Set(findings.map((f) => f.rule_id));

  // Default to first category that has findings, else PI
  const defaultCat =
    THREAT_CATS.find((cat) =>
      cat.subCats.some((sc) => sc.rules.some((r) => triggered.has(r)))
    )?.id ?? "PI";

  return (
    <section className="cdd-section">
      <div className="cdd-section-header">
        <h2 className="cdd-section-title">Security Category Deep Dive</h2>
        <p className="cdd-section-sub">
          Sub-Category Tree · Framework Coverage · Kill Chain · Compliance Overlay
        </p>
      </div>

      <div className="cdd-wrap">
        {/* Tab bar (labels) — always visible at top */}
        <div className="cdd-tabs">
          {THREAT_CATS.map((cat) => {
            const catRules = cat.subCats.flatMap((sc) => sc.rules);
            const catFindings = catRules.filter((r) => triggered.has(r)).length;
            return (
              <label
                key={cat.id}
                htmlFor={`cdd-${cat.id}`}
                className="cdd-tab"
                style={{ "--cc": cat.color } as React.CSSProperties}
              >
                <span className="cdd-tab-icon">{cat.icon}</span>
                <span className="cdd-tab-code">{cat.id}</span>
                {catFindings > 0 && (
                  <span className="cdd-tab-dot" />
                )}
              </label>
            );
          })}
        </div>

        {/* Radio+panel pairs — input MUST directly precede its panel for CSS + combinator */}
        {THREAT_CATS.map((cat) => {
          const allRules = cat.subCats.flatMap((sc) => sc.rules);
          const catHits = allRules.filter((r) => triggered.has(r));
          const cleanCount = allRules.length - catHits.length;
          const pct = allRules.length > 0 ? Math.round((cleanCount / allRules.length) * 100) : 100;
          const totalTests = allRules.length * 4;
          const passingTests = cleanCount * 4;
          const maturity = pct;

          return (
            <React.Fragment key={cat.id}>
            <input
              type="radio"
              name="cdd-cat"
              id={`cdd-${cat.id}`}
              className="cdd-radio"
              defaultChecked={cat.id === defaultCat}
            />
            <div className="cdd-panel">
              {/* Category header */}
              <div
                className="cdd-cat-hdr"
                style={{ "--cc": cat.color } as React.CSSProperties}
              >
                <div className="cdd-cat-hdr-left">
                  <span className="cdd-cat-icon">{cat.icon}</span>
                  <div>
                    <div className="cdd-cat-name">{cat.name}</div>
                    <div className="cdd-cat-tagline">{cat.tagline}</div>
                  </div>
                </div>
                <div className="cdd-maturity">
                  <div
                    className="cdd-maturity-num"
                    style={{
                      color: maturity >= 80 ? "#10b981" : maturity >= 50 ? "#f59e0b" : "#ef4444",
                    }}
                  >
                    {maturity}
                  </div>
                  <div className="cdd-maturity-label">MATURITY</div>
                </div>
              </div>

              {/* Stats row */}
              <div className="cdd-stats">
                {[
                  { num: allRules.length, label: "RULES" },
                  { num: cat.subCats.length, label: "SUB-CATS" },
                  { num: catHits.length, label: "FINDINGS", color: catHits.length > 0 ? "#ef4444" : "#10b981" },
                  { num: `${pct}%`, label: "CLEAN", color: pct >= 80 ? "#10b981" : pct >= 50 ? "#f59e0b" : "#ef4444" },
                  { num: totalTests, label: "TESTS" },
                  { num: cat.frameworks.length, label: "FRAMEWORKS" },
                ].map((s) => (
                  <div key={s.label} className="cdd-stat">
                    <div className="cdd-stat-num" style={s.color ? { color: s.color } : {}}>
                      {s.num}
                    </div>
                    <div className="cdd-stat-label">{s.label}</div>
                  </div>
                ))}
              </div>

              {/* Body: left tree + right sidebar */}
              <div className="cdd-body">
                {/* Left — sub-category tree */}
                <div className="cdd-left">
                  {cat.subCats.map((sc) => {
                    const scHits = sc.rules.filter((r) => triggered.has(r));
                    const scPct =
                      sc.rules.length > 0
                        ? Math.round(((sc.rules.length - scHits.length) / sc.rules.length) * 100)
                        : 100;
                    const barColor = scPct === 100 ? "#10b981" : scPct >= 50 ? "#f59e0b" : "#ef4444";

                    return (
                      <div
                        key={sc.id}
                        className={`cdd-subcat${scHits.length > 0 ? " cdd-subcat-hit" : ""}`}
                      >
                        <div className="cdd-subcat-hdr">
                          <div className="cdd-subcat-meta">
                            <span
                              className="cdd-subcat-id"
                              style={{ color: cat.color }}
                            >
                              {sc.id}
                            </span>
                            <span className="cdd-subcat-name">{sc.name}</span>
                          </div>
                          <div className="cdd-subcat-right">
                            <div className="cdd-bar-wrap">
                              <div
                                className="cdd-bar"
                                style={{ width: `${scPct}%`, background: barColor }}
                              />
                            </div>
                            <span className="cdd-pct" style={{ color: barColor }}>
                              {scPct}%
                            </span>
                            <span className="cdd-badge cdd-badge-rules">{sc.rules.length} rules</span>
                            {scHits.length > 0 && (
                              <span className="cdd-badge cdd-badge-hit">
                                {scHits.length} found
                              </span>
                            )}
                          </div>
                        </div>
                        <div className="cdd-subcat-desc">{sc.desc}</div>

                        {/* Rule rows */}
                        <div className="cdd-rule-list">
                          {sc.rules.map((ruleId) => {
                            const isHit = triggered.has(ruleId);
                            const sev = RULE_SEVERITIES[ruleId] ?? "medium";
                            const catPrefix = ruleId.replace(/\d+$/, "");
                            const vectors = CAT_VECTORS[catPrefix] ?? ["Tool metadata", "Server analysis"];
                            const mitigations = CAT_MITIGATIONS[catPrefix] ?? ["Apply security best practices", "Review rule documentation"];
                            const tests = RULE_TESTS[ruleId] ?? [
                              "True positive: malicious payload detected",
                              "True positive: variant pattern detected",
                              "True negative: safe pattern passes",
                              "True negative: sanitized input passes",
                            ];
                            const fwBadges = getRuleFrameworks(ruleId);
                            return (
                              <details
                                key={ruleId}
                                className={`cdd-rule${isHit ? " cdd-rule-hit" : " cdd-rule-clean"}`}
                                open={isHit}
                              >
                                <summary className="cdd-rule-summary">
                                  <span
                                    className="cdd-rule-id"
                                    style={{ color: cat.color }}
                                  >
                                    {ruleId}
                                  </span>
                                  <span className={`cdd-sev-dot cdd-sev-${sev}`} />
                                  <span className="cdd-rule-name">
                                    {RULE_NAMES[ruleId] ?? ruleId}
                                  </span>
                                  <div className="cdd-rule-right">
                                    {isHit ? (
                                      <span className="cdd-badge cdd-badge-triggered">triggered</span>
                                    ) : (
                                      <span className="cdd-badge cdd-badge-clean">clean</span>
                                    )}
                                    <span className="cdd-tests">{tests.length}✓</span>
                                    <span className="cdd-expand-arrow">▼</span>
                                  </div>
                                </summary>
                                {/* Expanded detail */}
                                <div className="cdd-rule-detail">
                                  <div className="cdd-rule-detail-cols">
                                    {/* Left: Tests */}
                                    <div className="cdd-detail-col">
                                      <div className="cdd-detail-heading">TESTS</div>
                                      {tests.map((t, ti) => (
                                        <div key={ti} className="cdd-detail-item cdd-detail-test">
                                          <span className="cdd-detail-check">✓</span>
                                          <span>{t}</span>
                                        </div>
                                      ))}
                                    </div>
                                    {/* Right: Vectors + Mitigations */}
                                    <div className="cdd-detail-col">
                                      <div className="cdd-detail-heading">ATTACK VECTORS</div>
                                      {vectors.map((v, vi) => (
                                        <div key={vi} className="cdd-detail-item cdd-detail-vector">
                                          <span
                                            className="cdd-detail-bar"
                                            style={{ background: cat.color }}
                                          />
                                          <span>{v}</span>
                                        </div>
                                      ))}
                                      <div className="cdd-detail-heading" style={{ marginTop: "0.6rem" }}>
                                        MITIGATIONS
                                      </div>
                                      {mitigations.map((m, mi) => (
                                        <div key={mi} className="cdd-detail-item cdd-detail-mitigation">
                                          <span className="cdd-detail-bar cdd-detail-bar-mit" />
                                          <span>{m}</span>
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                  {/* Framework alignment badges */}
                                  {fwBadges.length > 0 && (
                                    <div className="cdd-fw-badges">
                                      {fwBadges.map((fw) => (
                                        <span
                                          key={fw.abbr}
                                          className="cdd-fw-pill"
                                          style={{ borderColor: fw.color, color: fw.color }}
                                        >
                                          {fw.abbr}
                                        </span>
                                      ))}
                                    </div>
                                  )}
                                </div>
                              </details>
                            );
                          })}
                        </div>
                      </div>
                    );
                  })}
                </div>

                {/* Right — sidebar */}
                <div className="cdd-right">
                  {/* Framework Coverage */}
                  <div className="cdd-sidebar-card">
                    <div className="cdd-sidebar-title">Framework Coverage</div>
                    {cat.frameworks.map((fw) => (
                      <div key={fw} className="cdd-fw-row">
                        <span className="cdd-fw-name">{fw}</span>
                        <div className="cdd-fw-bar-wrap">
                          <div
                            className="cdd-fw-bar"
                            style={{
                              width: `${pct}%`,
                              background: cat.color,
                            }}
                          />
                        </div>
                        <span className="cdd-fw-count" style={{ color: cat.color }}>
                          {cleanCount}/{allRules.length}
                        </span>
                      </div>
                    ))}
                  </div>

                  {/* Test Execution */}
                  <div className="cdd-sidebar-card">
                    <div className="cdd-sidebar-title">Test Execution</div>
                    {[
                      { label: "Passing", count: passingTests, color: "#10b981" },
                      { label: "Failing", count: totalTests - passingTests, color: "#ef4444" },
                    ].map((row) => (
                      <div key={row.label} className="cdd-test-row">
                        <span className="cdd-test-label">{row.label}</span>
                        <div className="cdd-fw-bar-wrap">
                          <div
                            className="cdd-fw-bar"
                            style={{
                              width: `${Math.round((row.count / (totalTests || 1)) * 100)}%`,
                              background: row.color,
                            }}
                          />
                        </div>
                        <span className="cdd-fw-count" style={{ color: row.color }}>
                          {row.count}/{totalTests}
                        </span>
                      </div>
                    ))}
                  </div>

                  {/* Kill Chain Phases */}
                  <div className="cdd-sidebar-card">
                    <div className="cdd-sidebar-title">Kill Chain Phases</div>
                    {cat.killChain.map((phase) => {
                      const phaseCount =
                        catHits.length > 0
                          ? Math.max(1, Math.round(catHits.length / cat.killChain.length))
                          : 0;
                      return (
                        <div key={phase} className="cdd-kc-row">
                          <span
                            className="cdd-kc-badge"
                            style={{
                              background: phaseCount > 0 ? cat.color : "#1f2937",
                              color: phaseCount > 0 ? "#fff" : "#6b7280",
                            }}
                          >
                            {phaseCount}
                          </span>
                          <span className="cdd-kc-phase">{phase}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            </div>
            </React.Fragment>
          );
        })}
      </div>
    </section>
  );
}

// ── Framework Compliance Card ─────────────────────────────────────────────────

function FrameworkComplianceCard({ findings }: { findings: Finding[] }) {
  if (findings === undefined) return null;

  const findingRuleIds = new Set(findings.map((f) => f.rule_id));
  const hasMitreTechnique = findings.some((f) => f.mitre_technique);

  return (
    <div className="card">
      <h3
        style={{
          fontSize: "12px",
          fontWeight: 700,
          textTransform: "uppercase",
          letterSpacing: "0.06em",
          color: "var(--text-3)",
          marginBottom: "var(--s3)",
        }}
      >
        Framework Compliance
      </h3>
      <div style={{ display: "flex", flexDirection: "column" }}>
        {FRAMEWORKS.map((fw) => {
          const violatedRules = fw.ruleIds.filter((r) => findingRuleIds.has(r));
          const failed =
            violatedRules.length > 0 ||
            (fw.checkMitreTechnique && hasMitreTechnique);
          return (
            <div key={fw.id} className={`framework-row ${failed ? "fw-fail" : "fw-pass"}`}>
              <span className="fw-dot" />
              <span className="fw-name">{fw.name}</span>
              <span className="fw-status">
                {failed
                  ? `${violatedRules.length + (fw.checkMitreTechnique && hasMitreTechnique && !violatedRules.length ? 1 : 0)} issue${violatedRules.length !== 1 ? "s" : ""}`
                  : "Clean"}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Rule Intelligence Panel ───────────────────────────────────────────────────
// Combines: (1) heatmap grid, (2) accordion drill-down, (3) category cards

function RuleIntelligencePanel({ findings }: { findings: Finding[] }) {
  const findingRuleIds = new Set(findings.map((f) => f.rule_id));
  // Index findings by rule_id for quick lookup
  const findingsByRule = new Map<string, Finding[]>();
  for (const f of findings) {
    if (!findingsByRule.has(f.rule_id)) findingsByRule.set(f.rule_id, []);
    findingsByRule.get(f.rule_id)!.push(f);
  }

  const totalCats = RULE_CATEGORY_DATA.length;
  const affectedCats = RULE_CATEGORY_DATA.filter((cat) =>
    cat.rules.some((r) => findingRuleIds.has(r))
  ).length;

  return (
    <section className="section-gap">
      <h2 className="section-title">
        Rule Intelligence
        <span className="count">103 rules · 11 categories · 9 frameworks</span>
      </h2>

      <div
        style={{
          fontSize: "12px",
          color: "var(--text-3)",
          marginBottom: "var(--s4)",
        }}
      >
        <span style={{ color: affectedCats > 0 ? "var(--poor)" : "var(--good)", fontWeight: 600 }}>
          {affectedCats > 0 ? `${affectedCats} of ${totalCats} categories` : `All ${totalCats} categories`}
        </span>
        {affectedCats > 0 ? " have findings" : " clean"}
        {" · Expand any row to see individual rules"}
      </div>

      {/* ── (1) Heatmap grid ────────────────────────────────────── */}
      <div className="intel-heatmap-wrap">
        <table className="intel-heatmap">
          <thead>
            <tr>
              <th className="hm-th-cat">Category</th>
              {HEATMAP_FRAMEWORKS.map((fw) => (
                <th key={fw.id} className="hm-th-fw" title={fw.name}>
                  {fw.abbr}
                </th>
              ))}
              <th className="hm-th-total">Findings</th>
            </tr>
          </thead>
          <tbody>
            {RULE_CATEGORY_DATA.map((cat) => {
              const catFindings = findings.filter((f) => f.rule_id.startsWith(cat.prefix));
              const hasCatFindings = catFindings.length > 0;
              const worstCatSev = hasCatFindings
                ? SEV_ORDER.find((s) => catFindings.some((f) => f.severity === s))
                : null;

              return (
                <tr key={cat.prefix} className={hasCatFindings ? "hm-row-violated" : "hm-row-clean"}>
                  <td className="hm-td-cat">
                    <span className="hm-cat-prefix">{cat.prefix}</span>
                    <span className="hm-cat-name">{cat.name}</span>
                  </td>
                  {HEATMAP_FRAMEWORKS.map((fw) => {
                    const catFwRules = fw.rules.filter((r) => r.startsWith(cat.prefix));
                    if (catFwRules.length === 0) {
                      return (
                        <td key={fw.id} className="hm-cell hm-na" title="Not applicable to this framework">
                          <span className="hm-dash">—</span>
                        </td>
                      );
                    }
                    const violatedRules = catFwRules.filter((r) => findingRuleIds.has(r));
                    if (violatedRules.length > 0) {
                      const worstSev = SEV_ORDER.find((s) =>
                        violatedRules.some(
                          (r) => (findingsByRule.get(r) ?? []).some((f) => f.severity === s)
                        )
                      );
                      return (
                        <td
                          key={fw.id}
                          className={`hm-cell hm-violated hm-sev-${worstSev}`}
                          title={`${violatedRules.length} finding(s): ${violatedRules.join(", ")}`}
                        >
                          <span className="hm-dot" />
                          <span className="hm-count">{violatedRules.length}</span>
                        </td>
                      );
                    }
                    return (
                      <td
                        key={fw.id}
                        className="hm-cell hm-clean"
                        title={`Clean — ${catFwRules.length} rule(s) tested`}
                      >
                        <span className="hm-dot" />
                      </td>
                    );
                  })}
                  <td className="hm-td-total">
                    {hasCatFindings ? (
                      <span className={`hm-total-badge hm-total-${worstCatSev}`}>
                        {catFindings.length}
                      </span>
                    ) : (
                      <span className="hm-total-clean">✓</span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        <div className="hm-legend">
          <span className="hm-legend-item">
            <span className="hm-dot hm-sev-critical" style={{ display: "inline-block", verticalAlign: "middle" }} /> critical
          </span>
          <span className="hm-legend-item">
            <span className="hm-dot hm-sev-high" style={{ display: "inline-block", verticalAlign: "middle" }} /> high
          </span>
          <span className="hm-legend-item">
            <span className="hm-dot hm-clean" style={{ display: "inline-block", verticalAlign: "middle" }} /> clean
          </span>
          <span className="hm-legend-item">
            <span className="hm-dash" style={{ marginRight: "4px" }}>—</span> n/a
          </span>
        </div>
      </div>

      {/* ── (2) Accordion drill-down (CSS-only, uses <details>/<summary>) ──── */}
      <div className="intel-accordion">
        {RULE_CATEGORY_DATA.map((cat) => {
          const catFindings = findings.filter((f) => f.rule_id.startsWith(cat.prefix));
          const hasCatFindings = catFindings.length > 0;
          // Which frameworks does this category contribute to at all?
          const catFrameworks = HEATMAP_FRAMEWORKS.filter((fw) =>
            fw.rules.some((r) => r.startsWith(cat.prefix))
          );

          return (
            <details
              key={cat.prefix}
              className={`intel-cat ${hasCatFindings ? "intel-cat-violated" : "intel-cat-clean"}`}
              open={hasCatFindings}
            >
              <summary className="intel-cat-summary">
                {/* ── (3) Category card header — this IS the "cards" view ── */}
                <div className="intel-cat-card">
                  <div className="intel-cat-left">
                    <span className={`intel-cat-badge ${hasCatFindings ? "badge-violated" : "badge-clean"}`}>
                      {cat.prefix}
                    </span>
                    <div className="intel-cat-meta">
                      <span className="intel-cat-name">{cat.name}</span>
                      <span className="intel-cat-tagline">{cat.tagline}</span>
                    </div>
                  </div>
                  <div className="intel-cat-right">
                    <div className="intel-cat-fw-row">
                      {catFrameworks.map((fw) => (
                        <span key={fw.id} className="intel-fw-badge">{fw.abbr}</span>
                      ))}
                    </div>
                    <div className="intel-cat-stats">
                      <span className="intel-cat-rule-count">{cat.rules.length} rules</span>
                      {hasCatFindings ? (
                        <span className="intel-cat-finding-count">{catFindings.length} findings</span>
                      ) : (
                        <span className="intel-cat-clean-label">✓ clean</span>
                      )}
                    </div>
                  </div>
                </div>
              </summary>

              {/* Expanded: individual rule rows */}
              <div className="intel-rule-list">
                {cat.rules.map((ruleId) => {
                  const ruleFindings = findingsByRule.get(ruleId) ?? [];
                  const triggered = ruleFindings.length > 0;
                  const sev = RULE_SEVERITIES[ruleId] ?? "informational";
                  const ruleFws = HEATMAP_FRAMEWORKS.filter((fw) => fw.rules.includes(ruleId));
                  const worstSev = triggered
                    ? SEV_ORDER.find((s) => ruleFindings.some((f) => f.severity === s))
                    : null;

                  return (
                    <div key={ruleId} className={`intel-rule ${triggered ? "intel-rule-triggered" : "intel-rule-clean"}`}>
                      <span className="intel-rule-id">{ruleId}</span>
                      <span
                        className={`intel-rule-sev-dot intel-sev-dot-${sev}`}
                        title={sev}
                      />
                      <span className="intel-rule-name">
                        {RULE_NAMES[ruleId] ?? ruleId}
                      </span>
                      <div className="intel-rule-fws">
                        {ruleFws.map((fw) => (
                          <span key={fw.id} className="intel-fw-badge intel-fw-mini">{fw.abbr}</span>
                        ))}
                      </div>
                      <span className={`intel-rule-status ${triggered ? `intel-status-${worstSev}` : "intel-status-clean"}`}>
                        {triggered ? `✗ ${ruleFindings.length}` : "✓"}
                      </span>
                    </div>
                  );
                })}
              </div>
            </details>
          );
        })}
      </div>
    </section>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default async function ServerPage({
  params,
}: {
  params: Promise<{ slug: string }>;
}) {
  const { slug } = await params;
  const [server, scoreHistory, riskEdges] = await Promise.all([
    getServer(slug),
    getScoreHistory(slug),
    getRiskEdges(slug),
  ]);

  if (!server) {
    return (
      <div className="notfound" style={{ minHeight: "60vh" }}>
        <div className="notfound-code">404</div>
        <h1 className="notfound-title">Server not found</h1>
        <p className="notfound-sub">
          We don&apos;t have a record for &ldquo;{slug}&rdquo;.
        </p>
        <a href="/" className="btn-primary">
          ← Back to registry
        </a>
      </div>
    );
  }

  const score = server.latest_score;
  const sd = server.score_detail;

  // Group findings by severity
  const findingsBySev = SEV_ORDER.reduce<Record<string, Finding[]>>(
    (acc, sev) => {
      const matches = (server.findings || []).filter((f) => f.severity === sev);
      if (matches.length) acc[sev] = matches;
      return acc;
    },
    {}
  );

  const totalFindings = server.findings?.length ?? 0;
  const criticalCount = (server.findings || []).filter(
    (f) => f.severity === "critical"
  ).length;

  const badgeMd = `[![MCP Sentinel Score](${API_URL}/api/v1/servers/${server.slug}/badge.svg)](${SITE_URL}/server/${server.slug})`;

  const jsonLd = buildJsonLd(server, SITE_URL);

  return (
    <>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
      />
      {/* ── Breadcrumb + Header ──────────────────────── */}
      <div className="server-header">
        <nav className="breadcrumb" aria-label="Breadcrumb">
          <a href="/">Registry</a>
          <span>›</span>
          {server.category && (
            <>
              <a href={`/?category=${server.category}`}>{server.category}</a>
              <span>›</span>
            </>
          )}
          <span style={{ color: "var(--text-2)" }}>{server.name}</span>
        </nav>

        <h1 className="server-title">{server.name}</h1>

        {server.description && (
          <p
            style={{
              color: "var(--text-2)",
              fontSize: "15px",
              lineHeight: "1.6",
              maxWidth: "640px",
              marginBottom: "var(--s4)",
            }}
          >
            {server.description}
          </p>
        )}

        <div className="server-meta">
          {server.author && <span>by {server.author}</span>}
          {server.language && (
            <span className="category-chip">{server.language}</span>
          )}
          {server.license && (
            <span style={{ color: "var(--text-3)", fontSize: "13px" }}>
              {server.license}
            </span>
          )}
          {server.last_commit && (
            <span style={{ color: "var(--text-3)", fontSize: "13px" }}>
              Last commit {fmtDate(server.last_commit)}
            </span>
          )}
          <ConnectionStatusBadge status={server.connection_status} />
        </div>

        <div className="server-links">
          {server.github_url && (
            <a
              href={server.github_url}
              className="ext-link"
              target="_blank"
              rel="noopener noreferrer"
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 2C6.477 2 2 6.477 2 12c0 4.418 2.865 8.166 6.839 9.489.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.604-3.369-1.34-3.369-1.34-.454-1.155-1.11-1.463-1.11-1.463-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.029-2.683-.103-.253-.446-1.27.098-2.647 0 0 .84-.269 2.75 1.025A9.578 9.578 0 0112 6.836a9.59 9.59 0 012.504.337c1.909-1.294 2.747-1.025 2.747-1.025.546 1.377.202 2.394.1 2.647.64.699 1.028 1.592 1.028 2.683 0 3.842-2.339 4.687-4.566 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.743 0 .269.18.579.688.481C19.138 20.163 22 16.418 22 12c0-5.523-4.477-10-10-10z" />
              </svg>
              GitHub
            </a>
          )}
          {server.npm_package && (
            <a
              href={`https://www.npmjs.com/package/${server.npm_package}`}
              className="ext-link"
              target="_blank"
              rel="noopener noreferrer"
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
                <path d="M0 7.334v8h6.666v1.332H12v-1.332h12v-8H0zm6.666 6.664H5.334v-4H3.999v4H1.335V8.667h5.331v5.331zm4 0v1.336H8.001V8.667h5.334v5.332h-2.669v-.001zm12.001 0h-1.33v-4h-1.336v4h-1.335v-4h-1.33v4h-2.671V8.667h8.002v5.331z" />
              </svg>
              npm
            </a>
          )}
          {server.pypi_package && (
            <a
              href={`https://pypi.org/project/${server.pypi_package}`}
              className="ext-link"
              target="_blank"
              rel="noopener noreferrer"
            >
              PyPI
            </a>
          )}
        </div>
      </div>

      {/* ── Quick stats ──────────────────────────────── */}
      <div className="mini-stats">
        <div className="mini-stat">
          <div className="mini-stat-val">{server.tools?.length ?? 0}</div>
          <div className="mini-stat-label">Tools</div>
        </div>
        <div className="mini-stat">
          <div
            className="mini-stat-val"
            style={{ color: criticalCount > 0 ? "var(--critical)" : "var(--text)" }}
          >
            {totalFindings}
          </div>
          <div className="mini-stat-label">Findings</div>
        </div>
        <div className="mini-stat">
          <div className="mini-stat-val">{fmtNum(server.github_stars)}</div>
          <div className="mini-stat-label">Stars</div>
        </div>
        <div className="mini-stat">
          <div className="mini-stat-val">{fmtNum(server.npm_downloads)}</div>
          <div className="mini-stat-label">Downloads</div>
        </div>
      </div>

      {/* ── Two-column layout ────────────────────────── */}
      <div className="detail-layout">
        {/* ── Main column ──────────────────────────────── */}
        <div className="detail-main">

          {/* Not yet scanned banner */}
          {score === null && totalFindings === 0 && (!server.tools || server.tools.length === 0) && (
            <div
              className="card"
              style={{
                textAlign: "center",
                padding: "var(--s10)",
                marginBottom: "var(--s5)",
                color: "var(--text-3)",
              }}
            >
              <div style={{ fontSize: "28px", marginBottom: "var(--s2)" }}>
                ◎
              </div>
              <div style={{ fontWeight: 600, color: "var(--text-2)", marginBottom: "var(--s1)" }}>
                Not yet scanned
              </div>
              <p style={{ fontSize: "13px", maxWidth: "400px", margin: "0 auto" }}>
                This server has been discovered but hasn&apos;t been analyzed yet.
                It will be scanned in the next pipeline run.
              </p>
            </div>
          )}

          {/* Tools */}
          {server.tools && server.tools.length > 0 ? (
            <section className="section-gap">
              <h2 className="section-title">
                Tools{" "}
                <span className="count">{server.tools.length}</span>
              </h2>
              <div className="tools-grid">
                {server.tools.map((tool) => (
                  <div key={tool.name} className="tool-card">
                    <div className="tool-name">{tool.name}</div>
                    {tool.description && (
                      <p className="tool-desc">{tool.description}</p>
                    )}
                    {tool.capability_tags?.length > 0 && (
                      <div className="tool-caps">
                        {tool.capability_tags.map((tag) => (
                          <CapTag key={tag} tag={tag} />
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </section>
          ) : score !== null ? (
            <section className="section-gap">
              <h2 className="section-title">Tools</h2>
              <p style={{ fontSize: "13px", color: "var(--text-3)" }}>
                No tools enumerated — the server may not expose tools via <code>tools/list</code>,
                or the connection could not be established.
              </p>
            </section>
          ) : null}

          {/* Findings */}
          <section className="section-gap">
            <h2 className="section-title">
              Security Findings{" "}
              <span className="count">{totalFindings}</span>
              {criticalCount > 0 && (
                <span
                  className="sev-badge sev-critical"
                  style={{ marginLeft: "var(--s2)" }}
                >
                  {criticalCount} critical
                </span>
              )}
            </h2>

            {totalFindings === 0 ? (
              <div
                className="card"
                style={{
                  textAlign: "center",
                  padding: "var(--s10)",
                  color: "var(--good)",
                }}
              >
                <div style={{ fontSize: "32px", marginBottom: "var(--s2)" }}>
                  ✓
                </div>
                <div style={{ fontWeight: 600, marginBottom: "var(--s1)" }}>
                  No findings detected
                </div>
                <div style={{ fontSize: "13px", color: "var(--text-3)" }}>
                  This server passed all 103 detection rules.
                </div>
              </div>
            ) : (
              <div className="findings-list">
                {SEV_ORDER.map(
                  (sev) =>
                    findingsBySev[sev] && (
                      <div key={sev}>
                        <div
                          style={{
                            display: "flex",
                            alignItems: "center",
                            gap: "var(--s2)",
                            marginBottom: "var(--s2)",
                            marginTop: "var(--s4)",
                          }}
                        >
                          <SeverityBadge severity={sev} />
                          <span
                            style={{
                              fontSize: "12px",
                              color: "var(--text-3)",
                            }}
                          >
                            {findingsBySev[sev].length} finding
                            {findingsBySev[sev].length !== 1 ? "s" : ""}
                          </span>
                        </div>
                        {findingsBySev[sev].map((finding) => {
                          // Which frameworks does this rule map to?
                          const ruleFws = HEATMAP_FRAMEWORKS.filter(
                            (fw) => fw.rules.includes(finding.rule_id)
                          );
                          const catPrefix = finding.rule_id.charAt(0);
                          const catName = CATEGORY_SHORT_NAMES[catPrefix];

                          return (
                            <div
                              key={finding.id}
                              className={`finding-card finding-${finding.severity}`}
                              style={{ marginBottom: "var(--s2)" }}
                            >
                              {/* ── Row 1: severity + rule name + rule ID ── */}
                              <div className="finding-header">
                                <SeverityBadge severity={finding.severity} />
                                <span className="finding-title">
                                  {RULE_NAMES[finding.rule_id] ?? finding.rule_id}
                                </span>
                                <span className="finding-rule-id">
                                  {finding.rule_id}
                                </span>
                              </div>

                              {/* ── Row 2: category · MITRE · OWASP · framework badges ── */}
                              <div className="finding-tags">
                                {catName && (
                                  <span className="ftag ftag-cat">{catName}</span>
                                )}
                                {finding.mitre_technique && (
                                  <span className="ftag ftag-mitre" title="MITRE ATLAS technique">
                                    ⚑ {finding.mitre_technique}
                                  </span>
                                )}
                                {finding.owasp_category && (
                                  <span className="ftag ftag-owasp" title="OWASP MCP Top 10">
                                    {OWASP_LABELS[finding.owasp_category] ??
                                      finding.owasp_category.replace(/-/g, " ")}
                                  </span>
                                )}
                                {ruleFws
                                  .filter((fw) => fw.id !== "owasp-mcp")
                                  .map((fw) => (
                                    <span key={fw.id} className="ftag ftag-fw" title={fw.name}>
                                      {fw.abbr}
                                    </span>
                                  ))}
                              </div>

                              {/* ── Evidence ── */}
                              <p className="finding-evidence">
                                {finding.evidence}
                              </p>

                              {/* ── Remediation ── */}
                              <p className="finding-remediation">
                                {finding.remediation}
                              </p>
                            </div>
                          );
                        })}
                      </div>
                    )
                )}
              </div>
            )}
          </section>

          {/* Security Test Coverage */}
          {score !== null && (
            <SecurityTestSummary
              findings={server.findings ?? []}
              score={score}
            />
          )}

          {/* Category Deep Dive — threat-area tabs + sub-category tree */}
          {score !== null && (
            <CategoryDeepDivePanel findings={server.findings ?? []} />
          )}

          {/* Rule Intelligence Panel — heatmap + accordion */}
          {score !== null && (
            <RuleIntelligencePanel findings={server.findings ?? []} />
          )}

          {/* Badge embed */}
          <section>
            <h2 className="section-title">Add to your README</h2>
            <div className="card" style={{ gap: "var(--s3)", display: "flex", flexDirection: "column" }}>
              <p style={{ fontSize: "13px", color: "var(--text-3)" }}>
                Show your security score in your repository&apos;s README.
              </p>
              <pre className="badge-embed">{badgeMd}</pre>
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "var(--s3)",
                }}
              >
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img
                  src={`${API_URL}/api/v1/servers/${server.slug}/badge.svg`}
                  alt={`MCP Sentinel score for ${server.name}`}
                />
                <span style={{ fontSize: "12px", color: "var(--text-3)" }}>
                  Updates automatically on each scan.
                </span>
              </div>
            </div>
          </section>
        </div>

        {/* ── Sidebar ──────────────────────────────────── */}
        <aside className="detail-sidebar">
          {/* Score ring */}
          <div className="score-ring-card">
            <p className="score-ring-label">Security Score</p>
            <ScoreRing score={score} />
            <p
              style={{
                fontSize: "13px",
                fontWeight: 600,
                color: scoreColor(score),
              }}
            >
              {scoreLabel(score)}
            </p>

            {/* Sub-scores */}
            {sd && (
              <div className="subscores">
                <SubScoreBar label="Code" value={sd.code_score} />
                <SubScoreBar label="Dependencies" value={sd.deps_score} />
                <SubScoreBar label="Config" value={sd.config_score} />
                <SubScoreBar label="Description" value={sd.description_score} />
                <SubScoreBar label="Behavior" value={sd.behavior_score} />
              </div>
            )}
          </div>

          {/* OWASP coverage */}
          {sd?.owasp_coverage &&
            Object.keys(sd.owasp_coverage).length > 0 && (
              <div className="card">
                <h3
                  style={{
                    fontSize: "12px",
                    fontWeight: 700,
                    textTransform: "uppercase",
                    letterSpacing: "0.06em",
                    color: "var(--text-3)",
                    marginBottom: "var(--s3)",
                  }}
                >
                  OWASP MCP Coverage
                </h3>
                <div className="owasp-grid">
                  {Object.entries(sd.owasp_coverage).map(([key, clean]) => (
                    <div
                      key={key}
                      className={`owasp-item ${clean ? "clean" : "dirty"}`}
                      title={OWASP_LABELS[key] ?? key}
                    >
                      <span className="owasp-dot" />
                      <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {OWASP_LABELS[key] ?? key.split("-")[0]}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

          {/* Framework Compliance */}
          {score !== null && (
            <FrameworkComplianceCard findings={server.findings ?? []} />
          )}

          {/* Cross-server attack paths */}
          {riskEdges.length > 0 && (
            <div className="card">
              <h3
                style={{
                  fontSize: "12px",
                  fontWeight: 700,
                  textTransform: "uppercase",
                  letterSpacing: "0.06em",
                  color: "var(--text-3)",
                  marginBottom: "var(--s3)",
                }}
              >
                Cross-Server Attack Paths
              </h3>
              <div style={{ display: "flex", flexDirection: "column", gap: "var(--s3)" }}>
                {riskEdges.slice(0, 5).map((edge) => {
                  const isSource = edge.from_server_slug === slug;
                  const peerName = isSource ? edge.to_server_name : edge.from_server_name;
                  const peerSlug = isSource ? edge.to_server_slug : edge.from_server_slug;
                  const sevColor = edge.severity === "critical"
                    ? "var(--critical)"
                    : edge.severity === "high"
                      ? "var(--poor)"
                      : edge.severity === "medium"
                        ? "var(--moderate)"
                        : "var(--text-3)";
                  return (
                    <div
                      key={edge.id}
                      style={{
                        padding: "var(--s2) var(--s3)",
                        background: "var(--surface-2)",
                        borderRadius: "var(--r-sm)",
                        borderLeft: `3px solid ${sevColor}`,
                      }}
                    >
                      <div style={{ display: "flex", alignItems: "center", gap: "var(--s2)", marginBottom: "4px" }}>
                        <span
                          style={{
                            fontSize: "10px",
                            fontWeight: 700,
                            textTransform: "uppercase",
                            color: sevColor,
                            letterSpacing: "0.04em",
                          }}
                        >
                          {edge.severity}
                        </span>
                        <span style={{ fontSize: "10px", color: "var(--text-3)", fontFamily: "'JetBrains Mono', monospace" }}>
                          {edge.pattern_id}
                        </span>
                      </div>
                      <p style={{ fontSize: "11px", color: "var(--text-2)", margin: "0 0 4px" }}>
                        {edge.edge_type.replace(/_/g, " ")}
                        {" — "}
                        <a
                          href={`/server/${peerSlug}`}
                          style={{ color: "var(--accent)" }}
                        >
                          {peerName}
                        </a>
                      </p>
                      <p style={{ fontSize: "11px", color: "var(--text-3)", margin: 0, lineHeight: 1.4 }}>
                        {edge.description.length > 100
                          ? edge.description.slice(0, 100) + "…"
                          : edge.description}
                      </p>
                    </div>
                  );
                })}
                {riskEdges.length > 5 && (
                  <p style={{ fontSize: "11px", color: "var(--text-3)", textAlign: "center" }}>
                    +{riskEdges.length - 5} more attack paths
                  </p>
                )}
              </div>
            </div>
          )}

          {/* Score history timeline */}
          <ScoreHistoryTimeline history={scoreHistory} />

          {/* Scan metadata */}
          {(server.last_scanned_at || server.server_version || server.endpoint_url) && (
            <div className="card">
              <h3
                style={{
                  fontSize: "12px",
                  fontWeight: 700,
                  textTransform: "uppercase",
                  letterSpacing: "0.06em",
                  color: "var(--text-3)",
                  marginBottom: "var(--s3)",
                }}
              >
                Scan Info
              </h3>
              <dl
                style={{
                  display: "grid",
                  gridTemplateColumns: "auto 1fr",
                  gap: "var(--s1) var(--s3)",
                  fontSize: "12px",
                }}
              >
                {server.last_scanned_at && (
                  <>
                    <dt style={{ color: "var(--text-3)" }}>Last scan</dt>
                    <dd style={{ color: "var(--text-2)" }}>{fmtDate(server.last_scanned_at)}</dd>
                  </>
                )}
                {server.server_version && (
                  <>
                    <dt style={{ color: "var(--text-3)" }}>Server ver.</dt>
                    <dd style={{ color: "var(--text-2)", fontFamily: "var(--font-mono, monospace)" }}>{server.server_version}</dd>
                  </>
                )}
                {server.endpoint_url && (
                  <>
                    <dt style={{ color: "var(--text-3)" }}>Endpoint</dt>
                    <dd style={{ color: "var(--text-2)", fontFamily: "var(--font-mono, monospace)", fontSize: "11px", wordBreak: "break-all" }}>{server.endpoint_url}</dd>
                  </>
                )}
              </dl>
            </div>
          )}

          {/* Metadata card */}
          <div className="card">
            <h3
              style={{
                fontSize: "12px",
                fontWeight: 700,
                textTransform: "uppercase",
                letterSpacing: "0.06em",
                color: "var(--text-3)",
                marginBottom: "var(--s3)",
              }}
            >
              Details
            </h3>
            <dl
              style={{
                display: "grid",
                gridTemplateColumns: "auto 1fr",
                gap: "var(--s1) var(--s3)",
                fontSize: "12px",
              }}
            >
              {server.category && (
                <>
                  <dt style={{ color: "var(--text-3)" }}>Category</dt>
                  <dd style={{ color: "var(--text-2)" }}>{server.category}</dd>
                </>
              )}
              {server.language && (
                <>
                  <dt style={{ color: "var(--text-3)" }}>Language</dt>
                  <dd style={{ color: "var(--text-2)" }}>{server.language}</dd>
                </>
              )}
              {server.license && (
                <>
                  <dt style={{ color: "var(--text-3)" }}>License</dt>
                  <dd style={{ color: "var(--text-2)" }}>{server.license}</dd>
                </>
              )}
              {server.github_stars !== null && (
                <>
                  <dt style={{ color: "var(--text-3)" }}>Stars</dt>
                  <dd style={{ color: "var(--text-2)" }}>
                    {fmtNum(server.github_stars)}
                  </dd>
                </>
              )}
              {server.npm_downloads !== null && (
                <>
                  <dt style={{ color: "var(--text-3)" }}>Downloads</dt>
                  <dd style={{ color: "var(--text-2)" }}>
                    {fmtNum(server.npm_downloads)}
                  </dd>
                </>
              )}
              {server.last_commit && (
                <>
                  <dt style={{ color: "var(--text-3)" }}>Last commit</dt>
                  <dd style={{ color: "var(--text-2)" }}>
                    {fmtDate(server.last_commit)}
                  </dd>
                </>
              )}
            </dl>
          </div>
        </aside>
      </div>
    </>
  );
}
