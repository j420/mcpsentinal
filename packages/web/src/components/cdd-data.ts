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
};

// ── Framework membership (for rule badge computation) ─────────────────────

export const HEATMAP_FRAMEWORKS: { id: string; abbr: string; rules: string[] }[] = [
  { id: "owasp-mcp",     abbr: "OWASP MCP",  rules: Object.keys(RULE_NAMES) },
  { id: "owasp-agentic", abbr: "OWASP Agn",  rules: [
    "A1","A2","A7","A8","A9","B2","B5","B7","C1","C8","C9","C12","C13","C16",
    "D1","D3","D5","D7","E1","F1","F3","F5","F7","G1","G2","G4","G5",
    "H1","H2","H3","I1","I2","I3","I5","I6","I9","I10","I11","I12","I13","I14","I16",
    "J1","J2","J3","J5","J6","J7","K5","K6","K7","K8","K9","K10","K12","K13","K14","K15","K16","K17",
  ]},
  { id: "mitre",   abbr: "MITRE",    rules: [
    "A1","A4","A5","A7","A9","B5","C1","C3","C16","F1","F3","F6","F7",
    "G1","G2","G3","G4","G5","G7","H1","H2","H3",
    "I1","I2","I3","I4","I5","I6","I7","I8","I9","I10","I11","I12","I13","I14","I15","I16",
    "J1","J2","J3","J4","J5","J6","J7","K9","K14",
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
};

// ── Threat category taxonomy (11 categories, 28 sub-categories, 103 rules) ─

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
];
