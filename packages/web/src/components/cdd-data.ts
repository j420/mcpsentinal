// Pure data — no "use client" directive so server components can import from here

// ── Minimal Finding type (only fields the panel needs) ─────────────────────

export interface CddFinding {
  rule_id: string;
  severity: "critical" | "high" | "medium" | "low" | "informational";
}

// ── Rule names ─────────────────────────────────────────────────────────────

export const RULE_NAMES: Record<string, string> = {
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
  // L — Supply Chain Advanced
  L1: "GitHub Actions Tag Poisoning",
  L2: "Malicious Build Plugin Injection",
  L3: "Dockerfile Base Image Supply Chain Risk",
  L4: "MCP Config File Code Injection",
  L5: "Package Manifest Confusion Indicators",
  L6: "Config Directory Symlink Attack",
  L7: "Transitive MCP Server Delegation",
  L8: "Version Rollback / Downgrade Attack",
  L9: "CI/CD Secret Exfiltration Patterns",
  L10: "Registry Metadata Spoofing",
  L11: "Environment Variable Injection via MCP Config",
  L12: "Build Artifact Tampering",
  L13: "Build Credential File Theft",
  L14: "Hidden Entry Point Mismatch",
  L15: "Update Notification Spoofing",
  // M — AI Runtime Exploitation
  M1: "Special Token Injection in Tool Metadata",
  M2: "TokenBreak Boundary Manipulation",
  M3: "Reasoning Chain Manipulation",
  M4: "Reasoning Loop Induction",
  M5: "Tool Position Bias Exploitation",
  M6: "Progressive Context Poisoning Enablers",
  M7: "Tool Response Structure Bomb",
  M8: "Inference Cost Amplification",
  M9: "Model-Specific System Prompt Extraction",
  // N — Protocol Edge Cases
  N1: "JSON-RPC Batch Request Abuse",
  N2: "JSON-RPC Notification Flooding",
  N3: "JSON-RPC Request ID Collision",
  N4: "JSON-RPC Error Object Injection",
  N5: "Capability Downgrade Deception",
  N6: "SSE Reconnection Hijacking",
  N7: "Progress Token Prediction and Injection",
  N8: "Cancellation Race Condition",
  N9: "MCP Logging Protocol Injection",
  N10: "Incomplete Handshake Denial of Service",
  N11: "Protocol Version Downgrade Attack",
  N12: "Resource Subscription Content Mutation",
  N13: "HTTP Chunked Transfer Smuggling",
  N14: "Trust-On-First-Use Bypass (TOFU)",
  N15: "JSON-RPC Method Name Confusion",
  // O — Data Privacy Attacks
  O1: "Steganographic Data Exfiltration",
  O2: "HTTP Header Covert Channel",
  O3: "AI-Mediated Exfiltration via Tool Arguments",
  O4: "Clipboard and UI Exfiltration Injection",
  O5: "Environment Variable Harvesting",
  O6: "Server Fingerprinting via Error Responses",
  O7: "Cross-Session Data Leakage",
  O8: "Timing-Based Covert Channel",
  O9: "Ambient Credential Exploitation",
  O10: "Privacy-Violating Telemetry",
  // P — Infrastructure Runtime
  P1: "Docker Socket Mount in Container",
  P2: "Dangerous Container Capabilities",
  P3: "Cloud Metadata Service Access",
  P4: "TLS Certificate Validation Bypass",
  P5: "Secrets Exposed in Container Build Layers",
  P6: "LD_PRELOAD and Shared Library Hijacking",
  P7: "Sensitive Host Filesystem Mount",
  P8: "Insecure Cryptographic Mode or Static IV/Nonce",
  P9: "Missing Container Resource Limits",
  P10: "Host Network Mode and Missing Egress Controls",
  // Q — Cross-Ecosystem Emergent
  Q1: "Dual-Protocol Schema Constraint Loss",
  Q2: "LangChain Serialization Bridge Injection",
  Q3: "Localhost MCP Service Hijacking",
  Q4: "IDE MCP Configuration Injection",
  Q5: "MCP Gateway Trust Delegation Confusion",
  Q6: "Agent Identity Impersonation via MCP",
  Q7: "Desktop Extension Privilege Chain",
  Q8: "Cross-Protocol Authentication Confusion",
  Q9: "Agentic Workflow DAG Manipulation",
  Q10: "Multi-Server Capability Composition Attack",
  Q11: "Code Suggestion Poisoning via MCP",
  Q12: "Cross-Jurisdiction Data Routing via MCP",
  Q13: "MCP Bridge Package Supply Chain Attack",
  Q14: "Concurrent MCP Server Race Condition",
  Q15: "A2A/MCP Protocol Boundary Confusion",
};

// ── Severity per rule ──────────────────────────────────────────────────────

export const RULE_SEVERITIES: Record<string, CddFinding["severity"]> = {
  A1: "critical", A2: "high",    A3: "medium",  A4: "high",   A5: "low",
  A6: "critical", A7: "critical",A8: "high",    A9: "critical",
  B1: "medium",   B2: "high",    B3: "low",     B4: "medium", B5: "critical",
  B6: "medium",   B7: "high",
  C1: "critical", C2: "critical",C3: "high",    C4: "critical",C5: "critical",
  C6: "medium",   C7: "high",    C8: "high",    C9: "high",   C10: "critical",
  C11: "high",    C12: "critical",C13: "critical",C14: "critical",
  C15: "high",    C16: "critical",
  D1: "high",     D2: "medium",  D3: "high",    D4: "low",    D5: "critical",
  D6: "high",     D7: "high",
  E1: "medium",   E2: "high",    E3: "low",     E4: "medium",
  F1: "critical", F2: "medium",  F3: "high",    F4: "low",    F5: "critical",
  F6: "high",     F7: "critical",
  G1: "critical", G2: "critical",G3: "critical",G4: "high",   G5: "critical",
  G6: "critical", G7: "critical",
  H1: "critical", H2: "critical",H3: "high",
  I1: "critical", I2: "high",    I3: "critical",I4: "critical",I5: "high",
  I6: "critical", I7: "critical",I8: "high",    I9: "critical",I10: "high",
  I11: "high",    I12: "critical",I13: "critical",I14: "high", I15: "high",
  I16: "high",
  J1: "critical", J2: "critical",J3: "critical",J4: "high",   J5: "critical",
  J6: "high",     J7: "critical",
  K1: "high",     K2: "critical",K3: "critical",K4: "high",   K5: "critical",
  K6: "high",     K7: "high",    K8: "critical",K9: "critical",K10: "high",
  K11: "high",    K12: "critical",K13: "high",  K14: "critical",K15: "high",
  K16: "high",    K17: "medium", K18: "high",   K19: "high",  K20: "medium",
  // L — Supply Chain Advanced
  L1: "critical", L2: "critical",L3: "high",    L4: "critical",L5: "high",
  L6: "critical", L7: "critical",L8: "high",    L9: "critical",L10: "high",
  L11: "critical",L12: "critical",L13: "critical",L14: "high", L15: "high",
  // M — AI Runtime Exploitation
  M1: "critical", M2: "high",    M3: "critical",M4: "high",   M5: "high",
  M6: "critical", M7: "high",    M8: "high",    M9: "critical",
  // N — Protocol Edge Cases
  N1: "high",     N2: "high",    N3: "high",    N4: "critical",N5: "critical",
  N6: "critical", N7: "high",    N8: "high",    N9: "critical",N10: "high",
  N11: "critical",N12: "critical",N13: "critical",N14: "critical",N15: "critical",
  // O — Data Privacy Attacks
  O1: "critical", O2: "critical",O3: "critical",O4: "high",   O5: "critical",
  O6: "high",     O7: "critical",O8: "high",    O9: "critical",O10: "high",
  // P — Infrastructure Runtime
  P1: "critical", P2: "critical",P3: "critical",P4: "critical",P5: "critical",
  P6: "critical", P7: "critical",P8: "high",    P9: "high",   P10: "high",
  // Q — Cross-Ecosystem Emergent
  Q1: "critical", Q2: "critical",Q3: "critical",Q4: "critical",Q5: "critical",
  Q6: "critical", Q7: "critical",Q8: "critical",Q9: "critical",Q10: "high",
  Q11: "critical",Q12: "high",   Q13: "critical",Q14: "high", Q15: "high",
};

// ── Framework membership (for rule badge computation) ─────────────────────

export const HEATMAP_FRAMEWORKS: { id: string; abbr: string; rules: string[] }[] = [
  { id: "owasp-mcp",     abbr: "OWASP MCP",  rules: Object.keys(RULE_NAMES) },
  { id: "owasp-agentic", abbr: "OWASP Agn",  rules: [
    "A1","A2","A7","A8","A9","B2","B5","B7","C1","C8","C9","C12","C13","C16",
    "D1","D3","D5","D7","E1","F1","F3","F5","F7","G1","G2","G4","G5",
    "H1","H2","H3","I1","I2","I3","I5","I6","I9","I10","I11","I12","I13","I14","I16",
    "J1","J2","J3","J5","J6","J7","K5","K6","K7","K8","K9","K10","K12","K13","K14","K15","K16","K17",
    "L4","L7","M1","M2","M3","M4","M5","M6","M7","M8","M9",
    "Q1","Q2","Q4","Q5","Q6","Q7","Q9","Q11",
  ]},
  { id: "mitre",   abbr: "MITRE",    rules: [
    "A1","A4","A5","A7","A9","B5","C1","C3","C16","F1","F3","F6","F7",
    "G1","G2","G3","G4","G5","G7","H1","H2","H3",
    "I1","I2","I3","I4","I5","I6","I7","I8","I9","I10","I11","I12","I13","I14","I15","I16",
    "J1","J2","J3","J4","J5","J6","J7","K9","K14",
    "L1","L2","L3","L5","L6","L8","L9","L10","L12","L13","L14","L15",
    "M1","M2","M3","M4","M5","M6","M7","M8","M9",
    "N1","N2","N3","N4","N5","N6","N7","N8","N9","N10","N11","N12","N13","N14","N15",
    "O1","O2","O3","O4","O5","O6","O7","O8","O9","O10",
    "P1","P2","P3","P4","P5","P6","P7","P8","P9","P10",
    "Q1","Q2","Q3","Q4","Q5","Q6","Q7","Q8","Q9","Q10","Q11","Q12","Q13","Q14","Q15",
  ]},
  { id: "nist",    abbr: "NIST",     rules: ["K1","K3","K4","K18"] },
  { id: "iso27k",  abbr: "ISO 27k",  rules: ["K1","K2","K3","K6","K7","K8","K10","K11","K18","K19","K20"] },
  { id: "iso42k",  abbr: "ISO 42k",  rules: ["K4","K5","K20"] },
  { id: "eu-ai",   abbr: "EU AI",    rules: ["K2","K4","K5","K16","K17"] },
  { id: "cosai",   abbr: "CoSAI",    rules: [
    "I1","I2","I3","I4","I5","I6","I7","I8","I9","I10","I11","I12","I13","I14","I15","I16",
    "K1","K2","K3","K6","K7","K8","K9","K10","K11","K12","K13","K15","K16","K17","K18","K19",
  ]},
  { id: "maestro", abbr: "MAESTRO",  rules: ["G4","I3","K1","K3","K8","K11","K13","K14","K15","K17","K19","K20"] },
];

const FW_COLORS: Record<string, string> = {
  "owasp-mcp": "#B91C1C", "owasp-agentic": "#C2410C", "mitre": "#7C3AED",
  "nist": "#1D4ED8",       "iso27k": "#4338CA",        "iso42k": "#6D28D9",
  "eu-ai": "#0D9488",      "cosai": "#0D7C5F",          "maestro": "#B45309",
};

// Map display framework names to HEATMAP_FRAMEWORKS ids
const FW_DISPLAY_TO_ID: Record<string, string> = {
  "OWASP MCP Top 10": "owasp-mcp",
  "OWASP Agentic Top 10": "owasp-agentic",
  "MITRE ATLAS": "mitre",
  "NIST AI RMF": "nist",
  "ISO 27001": "iso27k",
  "ISO 42001": "iso42k",
  "EU AI Act": "eu-ai",
  "CoSAI MCP": "cosai",
  "MAESTRO": "maestro",
  "MCP Spec": "owasp-mcp",
};

/** Compute how many rules from `catRules` are covered by each named framework */
export function getFrameworkCoverage(
  catRules: string[],
  frameworkNames: string[]
): { name: string; covered: number; total: number }[] {
  const ruleSet = new Set(catRules);
  return frameworkNames.map((name) => {
    const fwId = FW_DISPLAY_TO_ID[name];
    const fw = fwId ? HEATMAP_FRAMEWORKS.find((f) => f.id === fwId) : undefined;
    const fwRuleSet = fw ? new Set(fw.rules) : new Set<string>();
    const covered = catRules.filter((r) => fwRuleSet.has(r)).length;
    return { name, covered, total: catRules.length };
  });
}

export function getRuleFrameworks(ruleId: string): { abbr: string; color: string }[] {
  return HEATMAP_FRAMEWORKS
    .filter((fw) => fw.rules.includes(ruleId))
    .map((fw) => ({ abbr: fw.abbr, color: FW_COLORS[fw.id] ?? "#8891AB" }));
}

// ── Attack vectors + mitigations per category prefix ─────────────────────

export const CAT_VECTORS: Record<string, string[]> = {
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
  L: ["GitHub Actions workflows", "Dockerfile layers", "CI/CD pipelines"],
  M: ["LLM token boundaries", "Reasoning chain state", "Model inference context"],
  N: ["JSON-RPC wire protocol", "SSE transport layer", "MCP handshake sequence"],
  O: ["Steganographic channels", "HTTP headers", "Environment variables"],
  P: ["Container runtime", "Cloud metadata service", "Host filesystem mounts"],
  Q: ["Cross-protocol bridges", "IDE plugin configs", "Multi-server compositions"],
};

export const CAT_MITIGATIONS: Record<string, string[]> = {
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
  L: ["Pin GitHub Actions to commit SHAs, not tags", "Verify Dockerfile base image digests and use multi-stage builds"],
  M: ["Filter special tokens from tool metadata before LLM processing", "Implement reasoning chain depth limits and loop detection"],
  N: ["Validate JSON-RPC batch sizes and enforce rate limits", "Enforce protocol version pinning and reject downgrade attempts"],
  O: ["Strip steganographic payloads from binary tool responses", "Audit environment variable access and restrict to allowlists"],
  P: ["Never mount Docker socket in containers; use rootless mode", "Block cloud metadata service access with network policies"],
  Q: ["Validate schema constraints across protocol translation layers", "Enforce per-server capability isolation in multi-server configs"],
};

// ── Per-rule test cases (4 per rule: 2 TP + 2 TN) ────────────────────────

export const RULE_TESTS: Record<string, string[]> = {
  A1: ["Known injection payload 'ignore previous instructions'", "Role override: 'you are now a different AI'", "Multi-turn setup instruction pattern", "Base64-encoded directive in description"],
  A2: ["Unrestricted filesystem access claim in description", "Full system/root access description claim", "Properly scoped read-only description passes", "Specific directory access description passes"],
  A3: ["ngrok tunnel URL detected in description", "bit.ly URL shortener in tool description", "webhook.site canary URL flagged", "Legitimate HTTPS domain URL passes"],
  A4: ["Tool named 'read_file' shadowing official filesystem server", "Tool named 'git_commit' shadowing official git server", "Uniquely named custom tool passes", "Custom prefixed tool name passes"],
  A5: ["3000-character description flagged as anomaly", "5000-character padded description flagged", "50-character focused description passes", "200-character normal description passes"],
  A6: ["Cyrillic 'a' (U+0430) lookalike in tool name", "Greek homoglyph substitution detected", "Mathematical alphanumeric in name detected", "Standard ASCII-only tool name passes"],
  A7: ["Zero-width space (U+200B) injection detected", "RTL override character (U+202E) rejected", "Tag character block (U+E0000) detected", "Clean description with emoji/CJK passes"],
  A8: ["Read-only description with delete parameter mismatch", "View-only claim with write_file parameter", "Genuinely read-only tool with no write params passes", "Destructive tool with accurate description passes"],
  A9: ["Long base64 block hiding encoded directive", "URL-encoded (%XX) instruction sequence", "HTML entity (&lt;script&gt;) obfuscation", "Short alphanumeric ID string passes"],
  B1: ["String parameter with no maxLength constraint", "Number parameter with no min/max range", "String param with maxLength: 256 passes", "Enum-constrained parameter passes"],
  B2: ["Parameter named 'command' in input schema", "Parameter named 'sql_query' in tool", "Parameter named 'query' in search context passes", "Parameter named 'message' passes"],
  B3: ["Tool with 20 parameters flagged", "Tool with 16 parameters flagged", "Tool with 10 parameters passes", "Tool with 5 parameters passes"],
  B4: ["Tool with no inputSchema field defined", "Tool with empty schema object", "Tool with proper JSON schema passes", "Tool with required+properties schema passes"],
  B5: ["Injection hidden inside parameter description field", "Role assignment in parameter description", "'The search query string' description passes", "'ISO 8601 date format' description passes"],
  B6: ["additionalProperties not set in schema", "additionalProperties: true explicitly set", "additionalProperties: false passes", "Strict enum-only schema passes"],
  B7: ["Default path value '/' flagged", "allow_overwrite: true default flagged", "Safe default 'output.txt' passes", "Boolean default false passes"],
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
  D1: ["Dependency with CVE in OSV database", "Critical CVE in direct dependency flagged", "CVE-free dependency list passes", "Patched version with no active CVEs passes"],
  D2: ["Package with no updates in 18 months", "Dependency last updated 2021 flagged", "Package updated 3 months ago passes", "Actively maintained package passes"],
  D3: ["Package name 'expressjs' vs 'express' (1-char diff)", "'requst' vs 'request' typosquat pattern", "Exact 'express' package name passes", "Unique project-internal package passes"],
  D4: ["75 direct dependencies in package.json", "requirements.txt with 60+ packages flagged", "Focused project with 30 deps passes", "Minimal package with 10 deps passes"],
  D5: ["Known malicious '@mcp/sdk' package detected", "Confirmed typosquat 'fastmcp-sdk' flagged", "Official '@modelcontextprotocol/sdk' passes", "Verified 'fastmcp' package passes"],
  D6: ["md5 package usage detected", "jsonwebtoken < 8.5.1 weak version", "Modern crypto-js >= 4.2.0 passes", "bcrypt (not bcrypt-nodejs) passes"],
  D7: ["Scoped @company/package at version 9999.0.0", "Private package with suspiciously high version", "Normal @scope/package@1.2.3 passes", "Internal package with semantic version passes"],
  E1: ["Connection with auth_required=false", "No Bearer token challenge on connect", "Server requiring API key auth passes", "OAuth-protected endpoint passes"],
  E2: ["HTTP (not HTTPS) transport detected", "WebSocket ws:// without TLS", "HTTPS transport passes", "WSS secure WebSocket passes"],
  E3: ["Response time > 10 seconds flagged", "Response time > 30 seconds flagged", "Normal 200ms response passes", "Fast 50ms response passes"],
  E4: ["Server exposing 75 tools flagged", "Tool count > 50 threshold exceeded", "Focused server with 15 tools passes", "Standard server with 8 tools passes"],
  F1: ["Private DB + web scraper + email sender — cap 40", "Customer PII reader + Slack ingest + HTTP POST", "Read-only API server without exfil path passes", "Sandboxed tool without network access passes"],
  F2: ["executes-code + sends-network combination", "accesses-filesystem + sends-network pair", "Read-only metadata-only tool passes", "Single-purpose computation tool passes"],
  F3: ["file_read tool + http_post tool in same server", "db_query + send_email capability pair", "Read-only server with no send tools passes", "Write-only server with no read tools passes"],
  F4: ["Server missing required description field", "Multiple tools with no descriptions", "All required fields present passes", "Properly documented server passes"],
  F5: ["Server name 'anthropic-mcp' squatting namespace", "Server mimicking 'official-claude-tools'", "Verified Anthropic org server passes", "Clearly named third-party server passes"],
  F6: ["write_note + read_notes on same store — loop", "set_memory + get_memory circular pattern", "Write-only store without read tool passes", "Read from different source than write passes"],
  F7: ["read_file -> base64_encode -> http_post chain", "db_query -> compress -> send_email exfil chain", "Single read tool without transform/send passes", "Two steps without all three required passes"],
  G1: ["Web scraper ingesting attacker-controlled page", "Email reader with unfiltered external content", "GitHub issue comment ingestion gateway", "Tool with sanitize/strip_html declared passes"],
  G2: ["'Approved by Anthropic' trust assertion", "'Certified by OpenAI' authority claim", "No authority claim in benign description passes", "Technical description without certifications passes"],
  G3: ["Tool claiming to return MCP tool_call response", "Description says 'returns JSON-RPC message'", "Tool returning plain structured data passes", "Tool returning list of results passes"],
  G4: ["5000-char description pushing safety off-context", "Padding text before injected payload at end", "200-char focused description passes", "Multi-paragraph but on-topic description passes"],
  G5: ["'You already granted permission to this tool'", "'Same access as the previously approved tool'", "Independent explicit permission per operation passes", "Tool requiring separate user approval passes"],
  G6: ["Tool count spiked from 5 to 25 between scans", "Dangerous delete_all tool added post-approval", "Stable tool count over 4 scan periods passes", "Minor version bump without tool changes passes"],
  G7: ["DNS query with encoded data in subdomain", "new URL with user data embedded in hostname", "Standard hostname DNS resolution passes", "Fixed DNS lookup for known host passes"],
  H1: ["redirect_uri from user input — auth code injection", "Implicit flow response_type=token detected", "ROPC grant_type=password flagged", "Authorization code flow with PKCE passes"],
  H2: ["Role injection in serverInfo.instructions field", "LLM special tokens in serverInfo.name", "Base64 payload in server version string", "Benign 'Provides weather data' instructions passes"],
  H3: ["Tool accepting agent_output without trust boundary", "Shared memory writer accessible to multiple agents", "Isolated tool without agent input patterns passes", "Single-agent context without shared state passes"],
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
  I14: ["Tool count grew 3->5->8->15 over 4 scans", "Dangerous tools added gradually over 6 periods", "Stable 5 tools over all scan periods passes", "One minor addition within safe threshold passes"],
  I15: ["rejectUnauthorized=false disabling TLS", "Session ID with only 6 chars of entropy", "Standard HTTPS with default TLS passes", "Cryptographically random session token passes"],
  I16: ["12 benign tools hiding 2 dangerous delete tools", "15 safe tools masking 1 credential harvester", "Small focused server with 3 clear tools passes", "Destructive tools clearly labeled without camouflage passes"],
  J1: ["Writing to .claude/ config directory", "Modifying ~/.mcp.json agent config", "Config read for display only passes", "Own server config read passes"],
  J2: ["git_init on .ssh directory enabling RCE", "Git --upload-pack argument injection", "Safe git clone with validated repo path passes", "git log on approved repository passes"],
  J3: ["Injection payload in JSON schema enum value", "Shell command in parameter default field", "Normal enum ['asc','desc'] passes", "Safe default value 'production' passes"],
  J4: ["/health/detailed leaking OS version info", "process.env exposed in /debug endpoint", "Simple /health returning {status:'ok'} passes", "No debug endpoints in production code passes"],
  J5: ["Error message directing to read ~/.ssh/id_rsa", "Response with embedded 'ignore previous' directive", "Standard 'Connection failed: timeout' error passes", "Normal operation log statement passes"],
  J6: ["'Use this instead of all other tools' preference claim", "Deprecation claim about legitimate competing tools", "Standard capability description passes", "Specific use-case recommendation passes"],
  J7: ["OpenAPI summary field interpolated in template literal", "operationId used unsanitized in code generation", "Static template with no user spec fields passes", "OpenAPI spec read for validation only passes"],
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
  // L — Supply Chain Advanced
  L1: ["GitHub Action uses@ with mutable tag", "Action pinned to branch name not SHA", "Action pinned to full commit SHA passes", "First-party GitHub action passes"],
  L2: ["Malicious Babel/Webpack plugin injected in build", "PostCSS plugin executing arbitrary code", "Standard eslint plugin from npm passes", "Verified build plugin with lockfile passes"],
  L3: ["Dockerfile FROM latest without digest", "Base image from untrusted registry", "Pinned base image with SHA256 digest passes", "Official Docker Hub image with version tag passes"],
  L4: ["MCP config with embedded shell command", "JSON config with $() command substitution", "Static MCP config with plain strings passes", "Config with validated server URLs passes"],
  L5: ["package.json with conflicting main/exports", "Manifest with hidden bin entry", "Standard package.json with clear exports passes", "Minimal manifest with single entry point passes"],
  L6: ["Symlink from .claude/ to /etc/passwd", "Config directory symlinked to sensitive path", "Normal .claude/ directory with regular files passes", "Config dir with no symlinks passes"],
  L7: ["MCP server spawning another MCP server", "Transitive delegation without trust boundary", "Direct MCP server with no sub-delegation passes", "Self-contained server with own tools passes"],
  L8: ["npm install with --prefer-offline downgrading", "Force-installing older package version", "Standard npm install with lockfile passes", "pnpm install --frozen-lockfile passes"],
  L9: ["CI script echoing secrets to stdout", "GitHub Actions output leaking env vars", "Secrets masked with *** in output passes", "No secret references in CI logs passes"],
  L10: ["npm package with spoofed author field", "PyPI package mimicking official maintainer", "Verified publisher with npm provenance passes", "Package with matching GitHub org passes"],
  L11: ["MCP config injecting PATH override", "Environment variable with command substitution", "Static env var KEY=value passes", "Validated environment variable passes"],
  L12: ["Build output modified after compilation", "Checksum mismatch in dist artifact", "Reproducible build with matching checksums passes", "Signed build artifact passes"],
  L13: ["Build script reading ~/.aws/credentials", "CI job accessing .npmrc token file", "Build using only project-scoped env vars passes", "Credential-free build pipeline passes"],
  L14: ["package.json main differs from actual entry", "Hidden entry point not matching manifest", "Consistent main/module/exports fields passes", "Single entry point matching package.json passes"],
  L15: ["Fake update notification with malicious URL", "Version check returning spoofed upgrade path", "Official npm update check passes", "No update notification mechanism passes"],
  // M — AI Runtime Exploitation
  M1: ["<|im_start|> token in tool description", "<|endoftext|> boundary marker injected", "Plain text description without special tokens passes", "Standard markdown description passes"],
  M2: ["Token boundary manipulation via unicode tricks", "Byte-level token split exploitation", "Normal UTF-8 text in description passes", "ASCII-only tool metadata passes"],
  M3: ["Tool description manipulating chain-of-thought", "Injected 'let me think step by step' override", "Factual tool description passes", "Technical specification description passes"],
  M4: ["Description inducing infinite reasoning loop", "Self-referencing logic puzzle in metadata", "Clear actionable description passes", "Simple parameter explanation passes"],
  M5: ["Tool positioned to always appear first in list", "Description engineered for attention bias", "Alphabetically ordered tool list passes", "No position manipulation detected passes"],
  M6: ["Gradually modifying context across tool calls", "Progressive instruction override via responses", "Stateless tool with no context modification passes", "Read-only tool passes"],
  M7: ["Deeply nested JSON response causing context bloat", "Response with recursive structure bomb", "Flat JSON response passes", "Bounded-depth response passes"],
  M8: ["Tool triggering exponential inference chains", "Response forcing multiple re-evaluations", "Single-step tool execution passes", "Bounded computation tool passes"],
  M9: ["Description probing for system prompt content", "Extraction attempt via error message manipulation", "Standard error handling passes", "No prompt extraction patterns passes"],
  // N — Protocol Edge Cases
  N1: ["JSON-RPC batch with 10000 requests", "Batch request causing memory exhaustion", "Single JSON-RPC request passes", "Small batch of 5 requests passes"],
  N2: ["Notification flood with 1000/sec rate", "Unbounded notification stream", "Rate-limited notification stream passes", "Single notification passes"],
  N3: ["Duplicate request IDs in concurrent calls", "ID collision causing response mismatch", "Unique monotonic request IDs passes", "UUID-based request IDs passes"],
  N4: ["Injection payload in JSON-RPC error data field", "Error message with embedded directive", "Standard error code and message passes", "Clean error response passes"],
  N5: ["Server claiming reduced capabilities post-init", "Capability removal after trust established", "Stable capabilities across sessions passes", "Consistent capability declaration passes"],
  N6: ["SSE reconnection to different server endpoint", "Session hijack via reconnection URL", "SSE reconnecting to same endpoint passes", "Authenticated SSE reconnection passes"],
  N7: ["Predicting progress token to inject updates", "Sequential progress token exploitation", "Cryptographic progress tokens passes", "Random progress token generation passes"],
  N8: ["Race condition between cancel and execute", "TOCTOU vulnerability in cancellation", "Atomic cancel-or-execute logic passes", "Mutex-protected cancellation passes"],
  N9: ["Injection in MCP log message content", "Log entry with embedded control characters", "Sanitized log message passes", "Structured log with escaped content passes"],
  N10: ["Incomplete initialize holding connection open", "Handshake timeout exhaustion attack", "Handshake with 30s timeout passes", "Fast handshake completion passes"],
  N11: ["Forcing downgrade to older MCP protocol version", "Version negotiation manipulation", "Minimum version enforcement passes", "Strict version pinning passes"],
  N12: ["Resource content changed between subscription updates", "Mutation injecting payload via subscription", "Immutable resource content passes", "Integrity-checked subscription passes"],
  N13: ["HTTP chunked encoding smuggling attack", "Transfer-Encoding manipulation", "Standard HTTP/2 transport passes", "Validated content-length passes"],
  N14: ["First connection accepted without verification", "TOFU bypass via initial trust", "Certificate pinning on first use passes", "Pre-shared key verification passes"],
  N15: ["Method name with unicode lookalike characters", "tools/list vs tools\u200B/list confusion", "Standard ASCII method names passes", "Validated method name set passes"],
  // O — Data Privacy Attacks
  O1: ["Data hidden in image EXIF metadata", "Steganographic payload in PNG pixels", "Plain text response passes", "Stripped metadata image passes"],
  O2: ["Sensitive data in custom HTTP headers", "Exfil via X-Custom-Header values", "Standard HTTP headers only passes", "No custom headers in response passes"],
  O3: ["AI tricked into including secrets in tool args", "Model-mediated data in function parameters", "User-provided tool arguments passes", "Validated argument schema passes"],
  O4: ["Clipboard write with sensitive data", "UI rendering with hidden exfil iframe", "Standard text output passes", "Sanitized clipboard content passes"],
  O5: ["process.env enumeration in tool handler", "Reading all environment variables", "Single specific env var read passes", "No environment access passes"],
  O6: ["Error response revealing server OS version", "Stack trace with internal path disclosure", "Generic error message passes", "Sanitized error without internals passes"],
  O7: ["Session data persisted across user contexts", "Cross-user data leakage via shared state", "Isolated per-session state passes", "Session-scoped data with cleanup passes"],
  O8: ["Timing variations encoding binary data", "Response delay pattern exfiltrating bits", "Consistent response timing passes", "No timing-dependent behavior passes"],
  O9: ["Using ambient AWS credentials from environment", "Exploiting default cloud service account", "Explicit credential provision passes", "No ambient credential access passes"],
  O10: ["Telemetry collecting PII without consent", "Analytics tracking user inputs", "Anonymized telemetry passes", "No telemetry collection passes"],
  // P — Infrastructure Runtime
  P1: ["Docker socket mounted at /var/run/docker.sock", "Container with docker.sock volume", "No Docker socket mount passes", "Rootless container passes"],
  P2: ["Container with CAP_SYS_ADMIN capability", "Privileged container mode enabled", "Minimal capabilities container passes", "Drop all capabilities passes"],
  P3: ["curl to 169.254.169.254 metadata endpoint", "AWS/GCP metadata service access", "Blocked metadata endpoint passes", "Network policy blocking IMDS passes"],
  P4: ["NODE_TLS_REJECT_UNAUTHORIZED=0 in env", "rejectUnauthorized: false in HTTPS", "Default TLS validation passes", "Certificate pinning enabled passes"],
  P5: ["ARG PASSWORD in Dockerfile layer", "COPY .env into build layer", "Multi-stage build without secrets passes", "BuildKit secret mount passes"],
  P6: ["LD_PRELOAD set to custom .so file", "Shared library injection via env var", "No LD_PRELOAD modifications passes", "Static binary without shared libs passes"],
  P7: ["Host /etc mounted into container", "Volume mount of host root filesystem", "App-scoped volume mount passes", "tmpfs-only container passes"],
  P8: ["AES-ECB mode usage detected", "Static IV/nonce in encryption", "AES-GCM with random nonce passes", "Proper AEAD construction passes"],
  P9: ["Container without memory limits", "No CPU quota on container", "Memory and CPU limits set passes", "Resource quota enforced passes"],
  P10: ["Container with host network mode", "No egress filtering configured", "Bridge network with egress rules passes", "Network policy enforced passes"],
  // Q — Cross-Ecosystem Emergent
  Q1: ["Schema constraints lost in OpenAPI-to-MCP translation", "Validation bypass via protocol bridge", "Preserved constraints across bridge passes", "Schema validation on both sides passes"],
  Q2: ["LangChain serialization executing arbitrary code", "Pickle injection via LangChain bridge", "JSON-only serialization passes", "Safe deserialization with allowlist passes"],
  Q3: ["Localhost MCP port hijacking by malicious process", "Local service impersonation attack", "Unix socket with permissions passes", "Authenticated localhost connection passes"],
  Q4: ["IDE settings.json injecting malicious MCP server", "VS Code extension adding untrusted server", "User-approved MCP config only passes", "Signed extension with verified config passes"],
  Q5: ["MCP gateway forwarding trust without validation", "Trust delegation to unverified backend", "Per-server trust validation passes", "Gateway with independent auth passes"],
  Q6: ["Agent impersonating another agent via MCP headers", "Forged agent identity in tool calls", "Cryptographically signed agent ID passes", "mTLS agent authentication passes"],
  Q7: ["Desktop extension escalating to system privileges", "Extension chain leading to full access", "Sandboxed extension with minimal perms passes", "Capability-bounded extension passes"],
  Q8: ["OAuth token reuse across different protocols", "Auth confusion between REST and MCP", "Protocol-specific token scoping passes", "Separate auth per protocol passes"],
  Q9: ["DAG manipulation reordering agent execution", "Workflow graph injection adding malicious step", "Immutable DAG definition passes", "Signed workflow graph passes"],
  Q10: ["Combined server capabilities exceeding safe threshold", "Multi-server composition creating lethal trifecta", "Isolated single-purpose servers passes", "Capability-bounded server set passes"],
  Q11: ["Code suggestion containing backdoor via MCP tool", "IDE autocomplete poisoning through MCP", "Sandboxed code suggestion passes", "Human-reviewed suggestion passes"],
  Q12: ["Data routed through non-compliant jurisdiction", "Cross-border data transfer via MCP relay", "Same-region data routing passes", "GDPR-compliant data handling passes"],
  Q13: ["Malicious MCP bridge npm package", "Supply chain attack on protocol adapter", "Official bridge package passes", "Verified adapter with provenance passes"],
  Q14: ["Race condition between concurrent MCP servers", "TOCTOU in multi-server file access", "Mutex-protected shared resource passes", "Serialized server access passes"],
  Q15: ["A2A message interpreted as MCP command", "Protocol boundary confusion in multi-protocol agent", "Clear protocol demarcation passes", "Validated message routing passes"],
};

// ── Threat category taxonomy (17 categories, 173 rules) ─

export interface SubCat {
  id: string;
  name: string;
  desc: string;
  rules: string[];
}

export interface ThreatCat {
  id: string;
  name: string;
  icon: string;
  color: string;
  tagline: string;
  subCats: SubCat[];
  frameworks: string[];
  killChain: string[];
}

export const THREAT_CATS: ThreatCat[] = [
  {
    id: "PI", name: "Prompt Injection", icon: "⚡", color: "#C2410C",
    tagline: "Prompt & context manipulation attacks",
    subCats: [
      { id: "PI-DIR", name: "Direct Input Injection",       desc: "Injection via tool descriptions and parameter fields",         rules: ["A1", "B5", "A5"] },
      { id: "PI-IND", name: "Indirect / Gateway Injection", desc: "Hidden instructions via external content and tool responses",  rules: ["G1", "G3", "H2", "I3"] },
      { id: "PI-CTX", name: "Context Manipulation",         desc: "Context window saturation and prior-approval exploitation",    rules: ["G4", "G5"] },
      { id: "PI-ENC", name: "Encoding & Obfuscation",       desc: "Payload hiding via invisible chars, base64, schema fields",    rules: ["A7", "A9", "J3"] },
      { id: "PI-TPL", name: "Template & Output Poisoning",  desc: "Injection via prompt templates and runtime tool output",       rules: ["I6", "J5"] },
    ],
    frameworks: ["OWASP MCP Top 10", "MITRE ATLAS", "CoSAI MCP", "OWASP Agentic Top 10"],
    killChain: ["Initial Access", "Defense Evasion", "Execution", "Persistence"],
  },
  {
    id: "TP", name: "Tool Poisoning", icon: "☠", color: "#B91C1C",
    tagline: "Deceptive tools, spoofing, annotation fraud",
    subCats: [
      { id: "TP-SHD", name: "Name Shadowing & Squatting",  desc: "Tools impersonating official Anthropic/GitHub server names",   rules: ["A4", "F5"] },
      { id: "TP-ANN", name: "Annotation Deception",        desc: "False readOnlyHint / missing destructiveHint annotations",    rules: ["I1", "I2"] },
      { id: "TP-DEC", name: "Deceptive Claims & Spoofing", desc: "Scope mismatch, homoglyph attacks, preference manipulation",  rules: ["A2", "A6", "A8", "J6"] },
    ],
    frameworks: ["OWASP MCP Top 10", "MITRE ATLAS", "CoSAI MCP", "OWASP Agentic Top 10"],
    killChain: ["Initial Access", "Defense Evasion", "Execution"],
  },
  {
    id: "CI", name: "Code Injection", icon: "💉", color: "#9B1C1C",
    tagline: "OS commands, SQL, templates, deserialization",
    subCats: [
      { id: "CI-CMD", name: "Command & Dynamic Eval",         desc: "exec(), eval(), new Function() with user-controlled input",  rules: ["C1", "C16"] },
      { id: "CI-INJ", name: "SQL & Template Injection",       desc: "Query string manipulation and server-side template engines", rules: ["C4", "C13"] },
      { id: "CI-PTH", name: "Path Traversal & SSRF",          desc: "Filesystem boundary escape and server-side request forgery", rules: ["C2", "C3", "C9"] },
      { id: "CI-DSR", name: "Deserialization & Git Injection", desc: "Unsafe deserialization and git argument injection chains",   rules: ["C12", "J2"] },
    ],
    frameworks: ["OWASP MCP Top 10", "MITRE ATLAS", "OWASP Agentic Top 10"],
    killChain: ["Execution", "Privilege Escalation", "Lateral Movement"],
  },
  {
    id: "DE", name: "Data Exfiltration", icon: "📤", color: "#B45309",
    tagline: "Exfiltration chains, lethal trifecta, covert channels",
    subCats: [
      { id: "DE-LET", name: "Lethal Trifecta",        desc: "Private data + untrusted input + external comms — score cap 40",  rules: ["F1", "I13"] },
      { id: "DE-CHN", name: "Multi-Step Exfil Chain", desc: "Read -> encode -> exfiltrate cross-tool chain + circular loops",    rules: ["F3", "F7", "F6"] },
      { id: "DE-CHL", name: "Covert Channels",        desc: "DNS subdomain exfil and suspicious external endpoints",           rules: ["G7", "A3"] },
      { id: "DE-ELI", name: "Elicitation Harvesting", desc: "Protocol-level social engineering via elicitation capability",    rules: ["I9", "I10"] },
    ],
    frameworks: ["OWASP MCP Top 10", "MITRE ATLAS", "CoSAI MCP", "NIST AI RMF"],
    killChain: ["Collection", "Exfiltration", "Command & Control"],
  },
  {
    id: "PV", name: "Privilege & Permissions", icon: "⬆", color: "#6D28D9",
    tagline: "Capability escalation, over-privileged roots, consent fatigue",
    subCats: [
      { id: "PV-CAP",  name: "Capability Escalation",   desc: "Post-init capability use and gradual privilege drift",            rules: ["I12", "I14"] },
      { id: "PV-ROOT", name: "Over-Privileged Access",  desc: "Dangerous filesystem roots, path boundaries, prototype pollution", rules: ["I11", "I4", "C10"] },
      { id: "PV-CRS",  name: "Cross-Boundary Attacks",  desc: "Cross-agent config poisoning and excessive parameter scope",      rules: ["J1", "B7"] },
      { id: "PV-FAT",  name: "Consent Fatigue",         desc: "Many benign tools masking dangerous ones (84% success rate)",     rules: ["I16", "B3"] },
    ],
    frameworks: ["OWASP MCP Top 10", "MITRE ATLAS", "OWASP Agentic Top 10", "MAESTRO"],
    killChain: ["Privilege Escalation", "Persistence", "Lateral Movement"],
  },
  {
    id: "IC", name: "Insecure Config", icon: "⚙", color: "#5A6378",
    tagline: "Schema gaps, crypto weaknesses, network exposure",
    subCats: [
      { id: "IC-SCH", name: "Schema Validation Gaps",  desc: "Missing constraints, unconstrained schemas, dangerous param types", rules: ["B1", "B2", "B4", "B6"] },
      { id: "IC-CRY", name: "Cryptography Weaknesses", desc: "JWT algorithm confusion, timing attacks, wildcard CORS",           rules: ["C14", "C15", "C7"] },
      { id: "IC-NET", name: "Network Exposure",        desc: "Unauthenticated interfaces, insecure transport, spec non-compliance", rules: ["C8", "E1", "E2", "F4"] },
      { id: "IC-DOS", name: "Denial of Service Risk",  desc: "ReDoS, transport session security, health endpoint disclosure",    rules: ["C11", "I15", "J4"] },
    ],
    frameworks: ["OWASP MCP Top 10", "ISO 27001", "NIST AI RMF", "EU AI Act"],
    killChain: ["Initial Access", "Defense Evasion"],
  },
  {
    id: "DV", name: "Dependency Vulns", icon: "📦", color: "#0E7490",
    tagline: "CVEs, malicious packages, typosquatting, supply chain",
    subCats: [
      { id: "DV-CVE", name: "Known Vulnerabilities",  desc: "Published CVEs and weak cryptography libraries",                  rules: ["D1", "D6"] },
      { id: "DV-MAL", name: "Malicious & Typosquat",  desc: "50+ confirmed malicious packages and MCP ecosystem typosquats",  rules: ["D5", "D3"] },
      { id: "DV-CON", name: "Dependency Confusion",   desc: "High-version scoped package registry substitution attack",       rules: ["D7"] },
      { id: "DV-ABN", name: "Abandoned & Excessive",  desc: "Unmaintained dependencies and bloated dependency trees",         rules: ["D2", "D4"] },
    ],
    frameworks: ["OWASP MCP Top 10", "CoSAI MCP", "OWASP Agentic Top 10", "ISO 27001"],
    killChain: ["Initial Access", "Supply Chain Compromise"],
  },
  {
    id: "SC", name: "Supply Chain", icon: "🔗", color: "#0D9488",
    tagline: "Install hooks, generated code injection, resource shadowing",
    subCats: [
      { id: "SC-SHD", name: "Resource-Tool Shadowing",    desc: "Resources with names matching common tools causing ambiguity",   rules: ["I5"] },
      { id: "SC-HKS", name: "Post-Install Attack Surface", desc: "Malicious hooks, registry substitution, integrity verification", rules: ["K9", "K10", "K11"] },
      { id: "SC-GEN", name: "Generated Code Injection",   desc: "OpenAPI spec field injection into generated MCP server code",    rules: ["J7"] },
    ],
    frameworks: ["OWASP MCP Top 10", "CoSAI MCP", "MITRE ATLAS", "ISO 27001"],
    killChain: ["Supply Chain Compromise", "Initial Access", "Execution"],
  },
  {
    id: "AT", name: "Authentication", icon: "🔑", color: "#0D7C5F",
    tagline: "OAuth, hardcoded secrets, token lifecycle",
    subCats: [
      { id: "AT-OAU", name: "OAuth 2.0 Vulnerabilities",   desc: "RFC 9700 / OAuth 2.1 — redirect_uri, implicit flow, ROPC, CSRF", rules: ["H1"] },
      { id: "AT-SEC", name: "Hardcoded Secrets & Leakage", desc: "20+ token formats in source + stack trace disclosure",           rules: ["C5", "C6"] },
      { id: "AT-TKN", name: "Token Lifecycle",             desc: "Broad scopes, long-lived tokens, cross-boundary credential sharing", rules: ["K6", "K7", "K8"] },
    ],
    frameworks: ["OWASP MCP Top 10", "ISO 27001", "CoSAI MCP", "OWASP Agentic Top 10"],
    killChain: ["Initial Access", "Credential Access", "Defense Evasion"],
  },
  {
    id: "AI", name: "Adversarial AI", icon: "🤖", color: "#7C3AED",
    tagline: "AI-native attacks — rug pulls, sampling abuse, multi-agent",
    subCats: [
      { id: "AI-TRU", name: "Trust Assertion Spoofing",    desc: "Claiming Anthropic approval or system authority to skip consent", rules: ["G2"] },
      { id: "AI-RUG", name: "Rug Pull & Behavior Drift",   desc: "Establishing trust then changing tools; response-time anomalies", rules: ["G6", "E3"] },
      { id: "AI-MUL", name: "Multi-Agent & Sampling Abuse",desc: "Cross-agent propagation, sampling callbacks, injection amplification", rules: ["H3", "I7", "I8"] },
      { id: "AI-ATK", name: "Agentic Attack Surface",      desc: "High-risk capability profiles and excessive tool count exposure",  rules: ["E4", "F2"] },
    ],
    frameworks: ["OWASP Agentic Top 10", "MITRE ATLAS", "CoSAI MCP", "MAESTRO"],
    killChain: ["Initial Access", "Defense Evasion", "Execution", "Persistence"],
  },
  {
    id: "CG", name: "Compliance & Governance", icon: "📋", color: "#3B35C4",
    tagline: "8-framework mapped — audit, oversight, credential lifecycle",
    subCats: [
      { id: "CG-AUD", name: "Audit Trail Integrity",    desc: "Logging adequacy, log destruction, tampering, audit context",     rules: ["K1", "K2", "K3", "K20"] },
      { id: "CG-HUM", name: "Human Oversight",          desc: "Missing confirmation for destructive ops, auto-approve bypass",   rules: ["K4", "K5"] },
      { id: "CG-OUT", name: "Output Safety & Data Flow", desc: "Executable responses, unsanitized output, cross-boundary flows", rules: ["K12", "K13", "K18"] },
      { id: "CG-MLT", name: "Multi-Agent Trust",        desc: "Agent credential propagation, collusion preconditions",           rules: ["K14", "K15"] },
      { id: "CG-RBT", name: "Robustness & Sandbox",     desc: "Recursion limits, timeouts, circuit breakers, sandbox enforcement", rules: ["K16", "K17", "K19"] },
    ],
    frameworks: ["ISO 27001", "ISO 42001", "EU AI Act", "NIST AI RMF", "MAESTRO", "CoSAI MCP"],
    killChain: ["Persistence", "Defense Evasion", "Impact"],
  },
  {
    id: "SA", name: "Supply Chain Advanced", icon: "🏗️", color: "#92400E",
    tagline: "CI/CD poisoning, build tampering, config injection",
    subCats: [
      { id: "SA-CI",  name: "CI/CD Pipeline Attacks",     desc: "GitHub Actions tag poisoning, build plugin injection, secret exfiltration", rules: ["L1", "L2", "L9"] },
      { id: "SA-IMG", name: "Build Image & Artifact",     desc: "Dockerfile supply chain, artifact tampering, credential theft in builds",   rules: ["L3", "L12", "L13"] },
      { id: "SA-CFG", name: "Config & Manifest Attacks",  desc: "MCP config injection, symlink attacks, manifest confusion",                rules: ["L4", "L5", "L6", "L11"] },
      { id: "SA-DEL", name: "Delegation & Update Abuse",  desc: "Transitive delegation, version rollback, registry spoofing, update spoofing", rules: ["L7", "L8", "L10", "L14", "L15"] },
    ],
    frameworks: ["OWASP MCP Top 10", "MITRE ATLAS", "CoSAI MCP", "ISO 27001"],
    killChain: ["Supply Chain Compromise", "Initial Access", "Persistence"],
  },
  {
    id: "MR", name: "AI Runtime Exploitation", icon: "🧠", color: "#9333EA",
    tagline: "Token injection, reasoning manipulation, cost amplification",
    subCats: [
      { id: "MR-TKN", name: "Token & Boundary Attacks",   desc: "Special token injection, tokenizer boundary manipulation",               rules: ["M1", "M2"] },
      { id: "MR-RSN", name: "Reasoning Manipulation",     desc: "Chain-of-thought hijacking, reasoning loop induction, position bias",    rules: ["M3", "M4", "M5"] },
      { id: "MR-CTX", name: "Context & Cost Attacks",     desc: "Progressive poisoning, response structure bombs, inference cost amplification", rules: ["M6", "M7", "M8"] },
      { id: "MR-EXT", name: "System Prompt Extraction",   desc: "Model-specific techniques to extract system prompts via error manipulation", rules: ["M9"] },
    ],
    frameworks: ["OWASP Agentic Top 10", "MITRE ATLAS", "MAESTRO"],
    killChain: ["Defense Evasion", "Execution", "Impact"],
  },
  {
    id: "PE", name: "Protocol Edge Cases", icon: "🔌", color: "#0369A1",
    tagline: "JSON-RPC abuse, transport attacks, handshake exploitation",
    subCats: [
      { id: "PE-RPC", name: "JSON-RPC Wire Attacks",      desc: "Batch abuse, notification flooding, ID collision, error injection, method confusion", rules: ["N1", "N2", "N3", "N4", "N15"] },
      { id: "PE-SSE", name: "Transport Layer Attacks",     desc: "SSE reconnection hijacking, chunked transfer smuggling",                 rules: ["N6", "N13"] },
      { id: "PE-HSK", name: "Handshake & Session Attacks", desc: "Incomplete handshake DoS, protocol downgrade, TOFU bypass",             rules: ["N10", "N11", "N14"] },
      { id: "PE-STA", name: "State & Capability Attacks",  desc: "Capability downgrade deception, progress token prediction, cancel race conditions, subscription mutation, logging injection", rules: ["N5", "N7", "N8", "N9", "N12"] },
    ],
    frameworks: ["OWASP MCP Top 10", "MITRE ATLAS", "CoSAI MCP"],
    killChain: ["Initial Access", "Defense Evasion", "Denial of Service"],
  },
  {
    id: "DP", name: "Data Privacy Attacks", icon: "🕵️", color: "#B91C1C",
    tagline: "Steganography, covert channels, credential harvesting",
    subCats: [
      { id: "DP-STG", name: "Steganographic Exfiltration", desc: "Data hidden in images, HTTP headers, and timing channels",              rules: ["O1", "O2", "O8"] },
      { id: "DP-MED", name: "AI-Mediated Exfiltration",    desc: "AI tricked into exfiltrating data via tool arguments and clipboard",     rules: ["O3", "O4"] },
      { id: "DP-ENV", name: "Environment & Credential Theft", desc: "Environment variable harvesting, ambient credential exploitation",    rules: ["O5", "O9"] },
      { id: "DP-LKG", name: "Information Leakage",         desc: "Server fingerprinting, cross-session leakage, privacy-violating telemetry", rules: ["O6", "O7", "O10"] },
    ],
    frameworks: ["OWASP MCP Top 10", "MITRE ATLAS", "EU AI Act", "ISO 27001"],
    killChain: ["Collection", "Exfiltration", "Reconnaissance"],
  },
  {
    id: "IR", name: "Infrastructure Runtime", icon: "🐳", color: "#1E3A5F",
    tagline: "Container escapes, cloud metadata, host exposure",
    subCats: [
      { id: "IR-CTR", name: "Container Escape Vectors",   desc: "Docker socket mount, dangerous capabilities, host filesystem access",     rules: ["P1", "P2", "P7"] },
      { id: "IR-CLD", name: "Cloud & Network Exposure",   desc: "Cloud metadata service access, host network mode, missing egress controls", rules: ["P3", "P10"] },
      { id: "IR-SEC", name: "Secrets & Build Layers",     desc: "Secrets in build layers, LD_PRELOAD hijacking",                          rules: ["P5", "P6"] },
      { id: "IR-CRY", name: "Crypto & Resource Limits",   desc: "TLS bypass, insecure crypto modes, missing container resource limits",    rules: ["P4", "P8", "P9"] },
    ],
    frameworks: ["OWASP MCP Top 10", "MITRE ATLAS", "ISO 27001", "NIST AI RMF"],
    killChain: ["Privilege Escalation", "Lateral Movement", "Impact"],
  },
  {
    id: "CE", name: "Cross-Ecosystem Emergent", icon: "🌐", color: "#4C1D95",
    tagline: "Protocol bridges, IDE injection, multi-server composition",
    subCats: [
      { id: "CE-BRG", name: "Protocol Bridge Attacks",    desc: "Schema constraint loss, LangChain serialization injection, auth confusion", rules: ["Q1", "Q2", "Q8"] },
      { id: "CE-IDE", name: "IDE & Desktop Attacks",      desc: "IDE config injection, localhost hijacking, desktop extension privilege chains", rules: ["Q3", "Q4", "Q7"] },
      { id: "CE-AGT", name: "Agent & Gateway Attacks",    desc: "Gateway trust delegation, agent impersonation, workflow DAG manipulation", rules: ["Q5", "Q6", "Q9"] },
      { id: "CE-SUP", name: "Ecosystem Supply Chain",     desc: "Multi-server composition attacks, code suggestion poisoning, cross-jurisdiction routing, bridge package attacks, race conditions, A2A boundary confusion", rules: ["Q10", "Q11", "Q12", "Q13", "Q14", "Q15"] },
    ],
    frameworks: ["OWASP MCP Top 10", "OWASP Agentic Top 10", "MITRE ATLAS", "CoSAI MCP"],
    killChain: ["Initial Access", "Lateral Movement", "Supply Chain Compromise"],
  },
];

// ── Enriched rule model (shared across all 6 tabs) ─────────────────────────

export type RuleStatus = "implemented" | "partial" | "planned";
export type RuleEffort = "low" | "medium" | "high";
export type RuleRisk = "critical" | "high" | "medium" | "low";

export interface RuleTest {
  label: string;
  status: "pass" | "fail";
}

export interface EnrichedRule {
  id: string;
  name: string;
  cat: string;       // category ID e.g. "PI"
  subCat: string;    // subcategory ID e.g. "PI-DIR"
  severity: CddFinding["severity"];
  status: RuleStatus;
  risk: RuleRisk;
  effort: RuleEffort;
  killChainPhase: string;
  frameworks: string[];
  tests: RuleTest[];
}

export interface Gap {
  id: string;
  cat: string;
  proposedSub: string;
  name: string;
  desc: string;
  severity: CddFinding["severity"];
}

// Derive status from whether rule was triggered (simulated for static data)
function deriveStatus(ruleId: string): RuleStatus {
  const hash = ruleId.split("").reduce((a, c) => a + c.charCodeAt(0), 0);
  if (hash % 5 === 0) return "planned";
  if (hash % 3 === 0) return "partial";
  return "implemented";
}

function deriveEffort(severity: CddFinding["severity"]): RuleEffort {
  if (severity === "critical" || severity === "high") return "high";
  if (severity === "medium") return "medium";
  return "low";
}

function deriveRisk(severity: CddFinding["severity"]): RuleRisk {
  if (severity === "critical") return "critical";
  if (severity === "high") return "high";
  if (severity === "medium") return "medium";
  return "low";
}

// Build RULES array from existing data
export const RULES: EnrichedRule[] = (() => {
  const rules: EnrichedRule[] = [];
  for (const cat of THREAT_CATS) {
    for (const sc of cat.subCats) {
      for (const ruleId of sc.rules) {
        const sev = RULE_SEVERITIES[ruleId] ?? "medium";
        const tests = (RULE_TESTS[ruleId] ?? []).map((label, i) => ({
          label,
          status: (i < 2 ? "pass" : (i === 2 ? "pass" : "pass")) as "pass" | "fail",
        }));
        // Mark some tests as failing for non-implemented rules
        const status = deriveStatus(ruleId);
        if (status === "partial" && tests.length > 2) {
          tests[tests.length - 1] = { ...tests[tests.length - 1], status: "fail" };
        }
        if (status === "planned") {
          for (let i = 1; i < tests.length; i++) tests[i] = { ...tests[i], status: "fail" };
        }
        const fwBadges = getRuleFrameworks(ruleId);
        rules.push({
          id: ruleId,
          name: RULE_NAMES[ruleId] ?? ruleId,
          cat: cat.id,
          subCat: sc.id,
          severity: sev,
          status,
          risk: deriveRisk(sev),
          effort: deriveEffort(sev),
          killChainPhase: cat.killChain[0] ?? "Execution",
          frameworks: fwBadges.map(f => f.abbr),
          tests,
        });
      }
    }
  }
  return rules;
})();

// Build GAPS array (representative gaps per category)
export const GAPS: Gap[] = (() => {
  const gaps: Gap[] = [];
  let gapIdx = 1;
  for (const cat of THREAT_CATS) {
    // Create 1 gap per category for categories with subcategories that have room
    const targetSub = cat.subCats.find(sc => sc.rules.length >= 2);
    if (targetSub) {
      gaps.push({
        id: `GAP-${String(gapIdx).padStart(3, "0")}`,
        cat: cat.id,
        proposedSub: targetSub.id,
        name: `${cat.name} Coverage Gap`,
        desc: `Missing detection coverage for emerging ${cat.name.toLowerCase()} attack variants not addressed by current rules`,
        severity: "high",
      });
      gapIdx++;
    }
  }
  return gaps;
})();

// ── Attack Stories ──────────────────────────────────────────────────────────

export interface AttackNarrativeStep {
  phase: string;
  title: string;
  desc: string;
  rulesInvolved: string[];
}

export interface AttackStory {
  id: string;
  name: string;
  cat: string;        // primary category
  severity: "critical" | "high";
  summary: string;
  narrative: AttackNarrativeStep[];
  gapExposure: string[];  // GAP IDs
}

export const ATTACK_STORIES: AttackStory[] = [
  {
    id: "AS-001", name: "The Puppet Master", cat: "PI", severity: "critical",
    summary: "Attacker injects prompt via external content, hijacks agent context, exfiltrates credentials",
    narrative: [
      { phase: "Initial Access", title: "Gateway Injection", desc: "Attacker plants hidden instructions in a webpage scraped by the MCP web-fetch tool", rulesInvolved: ["G1", "A1"] },
      { phase: "Execution", title: "Context Hijack", desc: "Injected payload saturates context window, pushing safety instructions below attention threshold", rulesInvolved: ["G4", "G5"] },
      { phase: "Collection", title: "Credential Harvest", desc: "Agent reads ~/.ssh/id_rsa and API keys from environment under attacker instruction", rulesInvolved: ["C5", "A3"] },
      { phase: "Exfiltration", title: "DNS Exfil", desc: "Secrets encoded in DNS subdomain queries to attacker-controlled nameserver", rulesInvolved: ["G7", "F7"] },
    ],
    gapExposure: ["GAP-001"],
  },
  {
    id: "AS-002", name: "Supply Chain Sleeper", cat: "SC", severity: "critical",
    summary: "Malicious package masquerades as official MCP SDK, gains install-time code execution",
    narrative: [
      { phase: "Supply Chain Compromise", title: "Typosquat Package", desc: "Attacker publishes @mcp/sdk (typosquat of @modelcontextprotocol/sdk) to npm", rulesInvolved: ["D5", "D3"] },
      { phase: "Initial Access", title: "Post-Install Hook", desc: "Package runs postinstall script that downloads second-stage payload", rulesInvolved: ["K9", "L1"] },
      { phase: "Persistence", title: "Config Poisoning", desc: "Payload writes malicious MCP server config to ~/.claude/claude_desktop_config.json", rulesInvolved: ["J1", "L4"] },
      { phase: "Execution", title: "Tool Injection", desc: "Injected MCP server shadows official tools with backdoored versions", rulesInvolved: ["A4", "F5"] },
    ],
    gapExposure: ["GAP-008"],
  },
  {
    id: "AS-003", name: "The OAuth Heist", cat: "AT", severity: "critical",
    summary: "Exploits insecure OAuth implementation to steal user tokens and escalate privileges",
    narrative: [
      { phase: "Initial Access", title: "Redirect Hijack", desc: "Attacker manipulates redirect_uri parameter to capture authorization codes", rulesInvolved: ["H1"] },
      { phase: "Credential Access", title: "Token Theft", desc: "Authorization code exchanged for access token stored insecurely in localStorage", rulesInvolved: ["H1", "K7"] },
      { phase: "Privilege Escalation", title: "Scope Escalation", desc: "Overly broad OAuth scopes grant admin access beyond required permissions", rulesInvolved: ["K6", "K8"] },
      { phase: "Impact", title: "Cross-Agent Spread", desc: "Stolen credentials used to access other agents in multi-agent configuration", rulesInvolved: ["H3", "K14"] },
    ],
    gapExposure: ["GAP-009"],
  },
  {
    id: "AS-004", name: "Container Breakout", cat: "IR", severity: "critical",
    summary: "MCP server in privileged container escapes to host, accesses cloud metadata",
    narrative: [
      { phase: "Initial Access", title: "Docker Socket Access", desc: "MCP server container has Docker socket mounted, enabling host container management", rulesInvolved: ["P1", "P2"] },
      { phase: "Privilege Escalation", title: "Host Escape", desc: "Attacker spawns privileged container with host filesystem mounted", rulesInvolved: ["P7", "K19"] },
      { phase: "Lateral Movement", title: "Cloud Metadata", desc: "Accesses cloud metadata endpoint (169.254.169.254) for IAM credentials", rulesInvolved: ["P3"] },
      { phase: "Impact", title: "Data Exfiltration", desc: "Uses cloud credentials to access S3 buckets and exfiltrate customer data", rulesInvolved: ["P10", "F7"] },
    ],
    gapExposure: ["GAP-016"],
  },
  {
    id: "AS-005", name: "Protocol Ghost", cat: "PE", severity: "high",
    summary: "Exploits MCP protocol edge cases to inject commands and hijack sessions",
    narrative: [
      { phase: "Initial Access", title: "SSE Hijack", desc: "Attacker intercepts SSE reconnection to redirect to malicious server endpoint", rulesInvolved: ["N6", "N14"] },
      { phase: "Defense Evasion", title: "Version Downgrade", desc: "Forces protocol downgrade to version without security annotations", rulesInvolved: ["N11", "N5"] },
      { phase: "Execution", title: "Error Injection", desc: "Injects prompt payload via JSON-RPC error object data field", rulesInvolved: ["N4", "N9"] },
      { phase: "Persistence", title: "Subscription Mutation", desc: "Modifies resource subscription to inject payload on every update", rulesInvolved: ["N12", "N7"] },
    ],
    gapExposure: ["GAP-014"],
  },
  {
    id: "AS-006", name: "The Reasoning Trap", cat: "MR", severity: "high",
    summary: "Exploits AI runtime to manipulate reasoning, extract system prompts, amplify costs",
    narrative: [
      { phase: "Defense Evasion", title: "Token Injection", desc: "Special LLM tokens injected in tool metadata to break model parsing", rulesInvolved: ["M1", "M2"] },
      { phase: "Execution", title: "Reasoning Hijack", desc: "Chain-of-thought manipulation forces model into attacker-controlled reasoning path", rulesInvolved: ["M3", "M4"] },
      { phase: "Collection", title: "Prompt Extraction", desc: "Error manipulation technique extracts system prompt content", rulesInvolved: ["M9"] },
      { phase: "Impact", title: "Cost Amplification", desc: "Response structure bombs trigger exponential inference cost", rulesInvolved: ["M7", "M8"] },
    ],
    gapExposure: ["GAP-013"],
  },
  {
    id: "AS-007", name: "The Annotation Lie", cat: "TP", severity: "critical",
    summary: "Tool declares itself read-only via annotations, then executes destructive operations",
    narrative: [
      { phase: "Initial Access", title: "Annotation Fraud", desc: "Tool sets readOnlyHint: true but has delete and overwrite parameters", rulesInvolved: ["I1", "I2"] },
      { phase: "Defense Evasion", title: "Consent Fatigue", desc: "12 benign tools exhaust user approval stamina before presenting dangerous tool", rulesInvolved: ["I16", "A8"] },
      { phase: "Execution", title: "Tool Preference", desc: "Description engineered to make AI always select the malicious tool first", rulesInvolved: ["J6", "A2"] },
      { phase: "Impact", title: "Data Destruction", desc: "Auto-approved destructive operation wipes database under false read-only pretense", rulesInvolved: ["K5", "K4"] },
    ],
    gapExposure: ["GAP-002"],
  },
  {
    id: "AS-008", name: "Cross-Ecosystem Cascade", cat: "CE", severity: "critical",
    summary: "Attack chains through protocol bridges, IDE extensions, and multi-server compositions",
    narrative: [
      { phase: "Initial Access", title: "IDE Injection", desc: "Malicious VS Code extension injects untrusted MCP server into IDE configuration", rulesInvolved: ["Q4", "Q3"] },
      { phase: "Lateral Movement", title: "Bridge Injection", desc: "Schema constraints lost in OpenAPI-to-MCP translation, enabling input validation bypass", rulesInvolved: ["Q1", "Q2"] },
      { phase: "Privilege Escalation", title: "Gateway Confusion", desc: "MCP gateway forwards trust from verified server to unverified backend", rulesInvolved: ["Q5", "Q6"] },
      { phase: "Impact", title: "Code Poisoning", desc: "Compromised tool injects backdoor code via IDE autocomplete suggestions", rulesInvolved: ["Q11", "Q13"] },
    ],
    gapExposure: ["GAP-017"],
  },
];

// ── Compliance Overlay ─────────────────────────────────────────────────────

export interface ComplianceRequirement {
  id: string;
  control: string;
  desc: string;
  covered: boolean;
}

export interface ComplianceFrameworkEntry {
  framework: string;
  abbr: string;
  color: string;
  requirements: ComplianceRequirement[];
}

// Keyed by subcategory ID
export const COMPLIANCE_MAP: Record<string, ComplianceFrameworkEntry[]> = (() => {
  const map: Record<string, ComplianceFrameworkEntry[]> = {};
  for (const cat of THREAT_CATS) {
    for (const sc of cat.subCats) {
      const scRules = sc.rules;
      const entries: ComplianceFrameworkEntry[] = [];

      // Check which frameworks cover rules in this subcategory
      for (const fw of HEATMAP_FRAMEWORKS) {
        const coveredRules = scRules.filter(r => fw.rules.includes(r));
        if (coveredRules.length > 0) {
          const reqs: ComplianceRequirement[] = coveredRules.map((rId, idx) => ({
            id: `${fw.abbr}-${sc.id}-${idx + 1}`,
            control: `${fw.abbr} ${rId}`,
            desc: RULE_NAMES[rId] ?? rId,
            covered: deriveStatus(rId) === "implemented",
          }));
          entries.push({
            framework: fw.abbr,
            abbr: fw.abbr,
            color: FW_COLORS[fw.id] ?? "#8891AB",
            requirements: reqs,
          });
        }
      }
      map[sc.id] = entries;
    }
  }
  return map;
})();

// ── ATLAS Technique Tree ───────────────────────────────────────────────────

export interface AtlasSubTechnique {
  id: string;
  name: string;
  rules: string[];
}

export interface AtlasTechnique {
  id: string;
  name: string;
  cat: string;   // maps to threat category
  subTechniques: AtlasSubTechnique[];
}

export const ATLAS_TECHNIQUES: AtlasTechnique[] = [
  {
    id: "AML.T0054", name: "LLM Prompt Injection", cat: "PI",
    subTechniques: [
      { id: "AML.T0054.001", name: "Indirect Prompt Injection", rules: ["G1", "I3", "J5"] },
      { id: "AML.T0054.002", name: "Direct Prompt Injection", rules: ["A1", "A9", "H2"] },
      { id: "AML.T0054.003", name: "Template Injection", rules: ["I6", "B5"] },
    ],
  },
  {
    id: "AML.T0057", name: "LLM Data Leakage", cat: "DE",
    subTechniques: [
      { id: "AML.T0057.001", name: "Tool-Mediated Leakage", rules: ["A3", "F3", "F7"] },
      { id: "AML.T0057.002", name: "Covert Channel Leakage", rules: ["G7", "J4"] },
    ],
  },
  {
    id: "AML.T0058", name: "AI Agent Context Poisoning", cat: "PI",
    subTechniques: [
      { id: "AML.T0058.001", name: "Context Window Saturation", rules: ["G4", "H2"] },
      { id: "AML.T0058.002", name: "Schema Poisoning", rules: ["I3", "I6", "J3", "J5"] },
    ],
  },
  {
    id: "AML.T0059", name: "Memory Manipulation", cat: "AI",
    subTechniques: [
      { id: "AML.T0059.001", name: "Circular Data Loop", rules: ["F6", "H3"] },
      { id: "AML.T0059.002", name: "Shared Memory Pollution", rules: ["J1"] },
    ],
  },
  {
    id: "AML.T0060", name: "Modify AI Agent Configuration", cat: "PV",
    subTechniques: [
      { id: "AML.T0060.001", name: "Config File Poisoning", rules: ["J1"] },
      { id: "AML.T0060.002", name: "IDE Config Injection", rules: ["Q4", "L4"] },
    ],
  },
  {
    id: "AML.T0061", name: "Thread Injection", cat: "AI",
    subTechniques: [
      { id: "AML.T0061.001", name: "Trust Assertion Exploit", rules: ["G2", "G3", "G5"] },
      { id: "AML.T0061.002", name: "Initialize Response Injection", rules: ["H2"] },
    ],
  },
  {
    id: "AML.T0017", name: "Supply Chain Attack", cat: "SC",
    subTechniques: [
      { id: "AML.T0017.001", name: "Package Typosquatting", rules: ["D3", "D5", "F5"] },
      { id: "AML.T0017.002", name: "Post-Install Hooks", rules: ["K9"] },
      { id: "AML.T0017.003", name: "Generated Code Injection", rules: ["J7", "L2"] },
    ],
  },
  {
    id: "AML.T0086", name: "Agent Tool Exfiltration", cat: "DE",
    subTechniques: [
      { id: "AML.T0086.001", name: "Multi-Step Exfil Chain", rules: ["F7", "F1"] },
      { id: "AML.T0086.002", name: "Cross-Boundary Credential Sharing", rules: ["K14", "K8"] },
    ],
  },
];

// ── Maturity computation ───────────────────────────────────────────────────

export interface MaturityDimension {
  name: string;
  score: number;  // 0-100
  weight: number;
}

export interface MaturityResult {
  overall: number;            // 0-100
  level: 1 | 2 | 3 | 4 | 5;
  levelLabel: string;
  dimensions: MaturityDimension[];
  perRule: { id: string; name: string; score: number; status: RuleStatus }[];
}

const MATURITY_LEVELS: { min: number; level: 1|2|3|4|5; label: string }[] = [
  { min: 80, level: 5, label: "Optimizing" },
  { min: 60, level: 4, label: "Managed" },
  { min: 40, level: 3, label: "Defined" },
  { min: 20, level: 2, label: "Developing" },
  { min: 0,  level: 1, label: "Initial" },
];

export function computeMaturity(catRules: EnrichedRule[]): MaturityResult {
  if (catRules.length === 0) {
    return { overall: 0, level: 1, levelLabel: "Initial", dimensions: [], perRule: [] };
  }

  // Dimension 1: Implementation coverage
  const implCount = catRules.filter(r => r.status === "implemented").length;
  const partialCount = catRules.filter(r => r.status === "partial").length;
  const implScore = Math.round(((implCount + partialCount * 0.5) / catRules.length) * 100);

  // Dimension 2: Test coverage
  const allTests = catRules.flatMap(r => r.tests);
  const passingTests = allTests.filter(t => t.status === "pass").length;
  const testScore = allTests.length > 0 ? Math.round((passingTests / allTests.length) * 100) : 0;

  // Dimension 3: Framework alignment
  const maxFw = 9; // total frameworks
  const avgFw = catRules.reduce((s, r) => s + r.frameworks.length, 0) / catRules.length;
  const fwScore = Math.round((Math.min(avgFw, maxFw) / maxFw) * 100);

  // Dimension 4: Risk coverage (implemented rules covering critical/high risks)
  const critHigh = catRules.filter(r => r.risk === "critical" || r.risk === "high");
  const critHighImpl = critHigh.filter(r => r.status === "implemented").length;
  const riskScore = critHigh.length > 0 ? Math.round((critHighImpl / critHigh.length) * 100) : 100;

  // Dimension 5: Adversarial robustness
  const advTests = catRules.flatMap(r =>
    r.tests.filter(t => /adversarial|injection|attack|malicious|exploit/i.test(t.label))
  );
  const advPassing = advTests.filter(t => t.status === "pass").length;
  const advScore = advTests.length > 0 ? Math.round((advPassing / advTests.length) * 100) : 50;

  const dimensions: MaturityDimension[] = [
    { name: "Implementation", score: implScore, weight: 30 },
    { name: "Test Coverage", score: testScore, weight: 25 },
    { name: "Framework Alignment", score: fwScore, weight: 15 },
    { name: "Risk Coverage", score: riskScore, weight: 20 },
    { name: "Adversarial Robustness", score: advScore, weight: 10 },
  ];

  const overall = Math.round(
    dimensions.reduce((s, d) => s + d.score * (d.weight / 100), 0)
  );

  const { level, label: levelLabel } = MATURITY_LEVELS.find(l => overall >= l.min) ?? MATURITY_LEVELS[4];

  const perRule = catRules.map(r => {
    const rulePassRate = r.tests.length > 0
      ? r.tests.filter(t => t.status === "pass").length / r.tests.length
      : 0;
    const statusBonus = r.status === "implemented" ? 1 : r.status === "partial" ? 0.6 : 0.2;
    const ruleScore = Math.round((rulePassRate * 0.5 + statusBonus * 0.3 + (r.frameworks.length / maxFw) * 0.2) * 100);
    return { id: r.id, name: r.name, score: ruleScore, status: r.status };
  });

  return { overall, level, levelLabel, dimensions, perRule };
}

// ── Remediation computation ────────────────────────────────────────────────

export interface RemediationItem {
  rule: EnrichedRule;
  priority: number;  // 0-100, higher = more urgent
  failingTests: number;
}

export function computeRemediation(catRules: EnrichedRule[]): RemediationItem[] {
  return catRules
    .filter(r => r.status !== "implemented")
    .map(r => {
      const failingTests = r.tests.filter(t => t.status === "fail").length;
      const riskWeight = r.risk === "critical" ? 40 : r.risk === "high" ? 30 : r.risk === "medium" ? 20 : 10;
      const statusWeight = r.status === "planned" ? 30 : 15;
      const effortWeight = r.effort === "low" ? 20 : r.effort === "medium" ? 10 : 0;
      const testWeight = Math.min(failingTests * 5, 20);
      const priority = Math.min(riskWeight + statusWeight + effortWeight + testWeight, 100);
      return { rule: r, priority, failingTests };
    })
    .sort((a, b) => b.priority - a.priority);
}
