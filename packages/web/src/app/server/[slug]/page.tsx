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
