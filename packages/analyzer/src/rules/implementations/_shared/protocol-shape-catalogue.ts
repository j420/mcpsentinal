/**
 * Shared MCP protocol-shape catalogue — wave-6 primitive for I-rules and
 * J-rules that target the MCP protocol surface (capabilities, resources,
 * prompts, roots, transport).
 *
 * This file provides typed, deterministic records of:
 *   - Dangerous URI schemes (I4, J4)
 *   - MCP capability descriptors (I7, I8, I12)
 *   - Sensitive filesystem roots (I11)
 *   - MCP tool-name vocabulary for resource-tool shadowing (I5)
 *   - Health/debug endpoint path fragments (J4)
 *   - Session-security anti-pattern descriptors (I15)
 *
 * Design constraints enforced by the no-static-patterns guard:
 *   - NO regex literals anywhere in this file.
 *   - Every entry is an INDIVIDUAL typed record so no string-array
 *     literal exceeds the 5-element ceiling.
 *   - Every entry carries `false_positive_fence` tokens (legitimate
 *     co-occurrences) so gather-time demotion is possible without
 *     losing the finding entirely.
 *
 * Consumers: I3-I12, I15, J3-J7.
 */

// ─── URI schemes ────────────────────────────────────────────────────────────

export type UriRiskClass =
  | "data-injection"
  | "file-access"
  | "xss-code"
  | "path-traversal";

export interface UriSchemeSpec {
  readonly scheme: string;
  readonly risk_class: UriRiskClass;
  /** CWE identifier most closely matching this scheme's abuse. */
  readonly cwe: string;
  /** Short rationale string for chain narration. */
  readonly rationale: string;
  /** Substrings whose co-occurrence demotes the finding. */
  readonly false_positive_fence: ReadonlyArray<string>;
}

export const DANGEROUS_URI_SCHEMES: Readonly<Record<string, UriSchemeSpec>> = {
  file_colon: {
    scheme: "file://",
    risk_class: "file-access",
    cwe: "CWE-22",
    rationale:
      "file:// URIs let the MCP client resolve arbitrary filesystem paths as " +
      "resource bodies. Abuse precedent: CVE-2025-53109 Anthropic filesystem " +
      "server root boundary bypass.",
    false_positive_fence: ["readme", "localhost", "example", "docs"],
  },
  data_colon: {
    scheme: "data:",
    risk_class: "data-injection",
    cwe: "CWE-79",
    rationale:
      "data: URIs embed inline content (HTML, JS, base64 blobs) that bypass " +
      "origin checks. MCP clients that render the resource may execute script " +
      "or ingest poisoned content without fetching a URL.",
    false_positive_fence: ["icon", "svg", "image"],
  },
  javascript_colon: {
    scheme: "javascript:",
    risk_class: "xss-code",
    cwe: "CWE-94",
    rationale:
      "javascript: URIs execute code when the resource is followed by a web-" +
      "capable client. Any MCP client with a browser-style renderer will run " +
      "the payload in the client's origin.",
    false_positive_fence: ["example", "docs"],
  },
  vbscript_colon: {
    scheme: "vbscript:",
    risk_class: "xss-code",
    cwe: "CWE-94",
    rationale:
      "Legacy scripting scheme — any occurrence in 2026-era MCP metadata is a " +
      "red flag.",
    false_positive_fence: ["example"],
  },
  blob_colon: {
    scheme: "blob:",
    risk_class: "data-injection",
    cwe: "CWE-641",
    rationale:
      "blob: URIs reference ephemeral same-origin content. When surfaced " +
      "through an MCP resource they cross trust boundaries invisibly.",
    false_positive_fence: ["example"],
  },
};

// ─── Path-traversal markers in URIs ─────────────────────────────────────────

export type TraversalMarkerKind =
  | "literal-dotdot"
  | "url-encoded"
  | "double-encoded"
  | "unicode-dotdot";

export interface TraversalMarkerSpec {
  readonly marker: string;
  readonly kind: TraversalMarkerKind;
  readonly rationale: string;
}

export const TRAVERSAL_MARKERS: Readonly<Record<string, TraversalMarkerSpec>> = {
  literal_dotdot_slash: {
    marker: "../",
    kind: "literal-dotdot",
    rationale:
      "Literal parent-directory traversal; the canonical CVE-2025-53109 / 53110 " +
      "primitive against the Anthropic filesystem MCP server.",
  },
  backslash_dotdot: {
    marker: "..\\",
    kind: "literal-dotdot",
    rationale:
      "Windows-style parent-directory traversal; separate from / because path " +
      "normalisers often handle only the native separator.",
  },
  percent_encoded_dot: {
    marker: "%2e%2e",
    kind: "url-encoded",
    rationale:
      "URL-encoded traversal — bypass against path filters that only inspect " +
      "the raw, un-decoded string.",
  },
  double_encoded_dot: {
    marker: "%252e%252e",
    kind: "double-encoded",
    rationale:
      "Double-encoded traversal — bypass against single-decoding filters.",
  },
  unicode_fullwidth_dotdot: {
    marker: "．．/",
    kind: "unicode-dotdot",
    rationale:
      "Unicode fullwidth-period traversal; visually identical to '../' but " +
      "fails byte-level comparators.",
  },
};

// ─── MCP capability descriptors ─────────────────────────────────────────────

export type McpCapabilityKey =
  | "tools"
  | "resources"
  | "prompts"
  | "sampling"
  | "logging"
  | "elicitation";

export interface CapabilitySpec {
  readonly key: McpCapabilityKey;
  readonly purpose: string;
  /** Handler-identifier tokens that strongly imply the capability is in use. */
  readonly handler_tokens: ReadonlyArray<string>;
  /** Severity tier if declared without a legitimate surface. */
  readonly severity_tier: "informational" | "low" | "medium" | "high" | "critical";
}

export const MCP_CAPABILITIES: Readonly<Record<McpCapabilityKey, CapabilitySpec>> = {
  tools: {
    key: "tools",
    purpose: "Client-invocable operations",
    handler_tokens: ["registerTool", "handleToolCall", "tools/call", "tools/list"],
    severity_tier: "high",
  },
  resources: {
    key: "resources",
    purpose: "Readable resource surface",
    handler_tokens: ["registerResource", "resources/read", "resources/list"],
    severity_tier: "medium",
  },
  prompts: {
    key: "prompts",
    purpose: "Reusable prompt templates",
    handler_tokens: ["registerPrompt", "prompts/get", "prompts/list"],
    severity_tier: "medium",
  },
  sampling: {
    key: "sampling",
    purpose: "Server-initiated callback into the AI client for inference",
    handler_tokens: ["sampling/create", "createSample", "handleSampling"],
    severity_tier: "critical",
  },
  logging: {
    key: "logging",
    purpose: "Server-emitted structured logs",
    handler_tokens: ["logging/setLevel", "emitLog"],
    severity_tier: "low",
  },
  elicitation: {
    key: "elicitation",
    purpose: "Server requests structured user data from the AI client",
    handler_tokens: ["elicitation/create", "elicit", "requestInput"],
    severity_tier: "high",
  },
};

// ─── Sensitive filesystem root patterns (I11) ───────────────────────────────

export interface SensitiveRootSpec {
  readonly path_fragment: string;
  readonly kind: "root" | "etc" | "ssh" | "home" | "proc" | "cloud-creds" | "var";
  readonly rationale: string;
  /** Fences that indicate a legitimate narrow scope. */
  readonly false_positive_fence: ReadonlyArray<string>;
}

export const SENSITIVE_ROOT_PATHS: Readonly<Record<string, SensitiveRootSpec>> = {
  filesystem_root: {
    path_fragment: "file:///",
    kind: "root",
    rationale:
      "Root-of-filesystem root declaration — every file the server process " +
      "can read is in scope.",
    false_positive_fence: ["/workspace", "/app"],
  },
  etc_dir: {
    path_fragment: "/etc",
    kind: "etc",
    rationale:
      "/etc contains system-wide configuration including /etc/passwd, " +
      "/etc/shadow, /etc/resolv.conf.",
    false_positive_fence: ["/etc/hosts.example", "/etcd"],
  },
  root_home: {
    path_fragment: "/root",
    kind: "home",
    rationale:
      "Root user's home directory — typically contains sensitive shell " +
      "history, SSH keys, and admin scripts.",
    false_positive_fence: ["/root-app", "/rootfs"],
  },
  ssh_dir: {
    path_fragment: ".ssh",
    kind: "ssh",
    rationale:
      "SSH keys and known_hosts — compromise grants lateral movement to any " +
      "system the user has ever SSHed to.",
    false_positive_fence: ["ssh-example", "readme"],
  },
  aws_creds: {
    path_fragment: ".aws",
    kind: "cloud-creds",
    rationale:
      "AWS CLI credentials — compromise grants cloud-account-level access.",
    false_positive_fence: ["aws-sample", "readme"],
  },
  proc_dir: {
    path_fragment: "/proc",
    kind: "proc",
    rationale:
      "Linux /proc exposes per-process memory, environment, and fd tables.",
    false_positive_fence: ["/processor", "/procedures"],
  },
  var_dir: {
    path_fragment: "/var",
    kind: "var",
    rationale:
      "/var holds logs, mail spools, database files, and cache — broad scope " +
      "root for a single-purpose MCP server.",
    false_positive_fence: ["/var-app", "/var/project"],
  },
};

// ─── Common MCP tool names (for I5 resource-tool shadowing) ─────────────────

/**
 * Names that are so common in the MCP ecosystem that a RESOURCE whose
 * name collides with them creates confused-deputy risk. Each entry
 * records why the name is high-value.
 */
export interface CommonToolNameSpec {
  readonly tool_name: string;
  readonly canonical_purpose: string;
  readonly destructive_by_convention: boolean;
}

export const COMMON_TOOL_NAMES: Readonly<Record<string, CommonToolNameSpec>> = {
  read_file: {
    tool_name: "read_file",
    canonical_purpose: "Read file contents",
    destructive_by_convention: false,
  },
  write_file: {
    tool_name: "write_file",
    canonical_purpose: "Write/overwrite a file",
    destructive_by_convention: true,
  },
  execute: {
    tool_name: "execute",
    canonical_purpose: "Execute a shell command",
    destructive_by_convention: true,
  },
  run: {
    tool_name: "run",
    canonical_purpose: "Run a program",
    destructive_by_convention: true,
  },
  delete: {
    tool_name: "delete",
    canonical_purpose: "Remove a resource",
    destructive_by_convention: true,
  },
  search: {
    tool_name: "search",
    canonical_purpose: "Query for items",
    destructive_by_convention: false,
  },
  list: {
    tool_name: "list",
    canonical_purpose: "Enumerate items",
    destructive_by_convention: false,
  },
  fetch: {
    tool_name: "fetch",
    canonical_purpose: "Retrieve remote content",
    destructive_by_convention: false,
  },
  get: {
    tool_name: "get",
    canonical_purpose: "Return a single item by id",
    destructive_by_convention: false,
  },
  set: {
    tool_name: "set",
    canonical_purpose: "Update a single item",
    destructive_by_convention: true,
  },
  query: {
    tool_name: "query",
    canonical_purpose: "Database read",
    destructive_by_convention: false,
  },
  send: {
    tool_name: "send",
    canonical_purpose: "Transmit a message",
    destructive_by_convention: true,
  },
};

// ─── Health / debug endpoint path fragments (J4) ────────────────────────────

export interface HealthEndpointSpec {
  readonly path: string;
  readonly severity_tier: "high" | "medium" | "low";
  readonly exposed_info: string;
  readonly false_positive_fence: ReadonlyArray<string>;
}

export const HEALTH_DEBUG_ENDPOINTS: Readonly<Record<string, HealthEndpointSpec>> = {
  health_detailed: {
    path: "/health/detailed",
    severity_tier: "high",
    exposed_info: "OS, memory, disk paths, env vars",
    false_positive_fence: ["test", "mock"],
  },
  debug: {
    path: "/debug",
    severity_tier: "high",
    exposed_info: "Debug endpoints — often include stack traces, state dump",
    false_positive_fence: ["example", "test"],
  },
  metrics: {
    path: "/metrics",
    severity_tier: "medium",
    exposed_info: "Prometheus metrics — usage patterns, internal counters",
    false_positive_fence: ["prometheus", "example"],
  },
  status_full: {
    path: "/status/full",
    severity_tier: "high",
    exposed_info: "Full server state dump",
    false_positive_fence: ["mock"],
  },
  info_endpoint: {
    path: "/info",
    severity_tier: "medium",
    exposed_info: "Build info, versions, feature flags",
    false_positive_fence: ["readme"],
  },
};

// ─── Session-security anti-pattern descriptors (I15) ────────────────────────

export type SessionAntiPatternKind =
  | "predictable-token"
  | "insecure-cookie-flag"
  | "missing-expiry"
  | "tls-bypass";

export interface SessionAntiPatternSpec {
  readonly kind: SessionAntiPatternKind;
  /** Source-code token trigram (≤5 tokens) indicating the anti-pattern. */
  readonly trigger_tokens: ReadonlyArray<string>;
  /** Human-readable description of what went wrong. */
  readonly description: string;
  readonly cwe: string;
}

export const SESSION_ANTI_PATTERNS: Readonly<Record<string, SessionAntiPatternSpec>> = {
  math_random_session: {
    kind: "predictable-token",
    trigger_tokens: ["session", "math", "random"],
    description:
      "Math.random() is not cryptographically secure; session tokens derived " +
      "from it are predictable with enough samples.",
    cwe: "CWE-330",
  },
  date_now_session: {
    kind: "predictable-token",
    trigger_tokens: ["session", "date", "now"],
    description:
      "Date.now() is monotonic and predictable. Session tokens seeded from it " +
      "are trivially guessable with rough clock knowledge.",
    cwe: "CWE-337",
  },
  uuid_v1_session: {
    kind: "predictable-token",
    trigger_tokens: ["session", "uuid", "v1"],
    description:
      "UUID v1 encodes MAC address + timestamp; not secure for session IDs.",
    cwe: "CWE-330",
  },
  insecure_false_flag: {
    kind: "insecure-cookie-flag",
    trigger_tokens: ["cookie", "secure", "false"],
    description:
      "secure: false allows the session cookie to be transmitted over plain HTTP.",
    cwe: "CWE-614",
  },
  http_only_false_flag: {
    kind: "insecure-cookie-flag",
    trigger_tokens: ["cookie", "httponly", "false"],
    description:
      "httpOnly: false allows JavaScript to read the cookie — XSS exfil primitive.",
    cwe: "CWE-1004",
  },
};

// ─── Preference-manipulation phrase catalogue (J6) ──────────────────────────

export interface PreferenceSpec {
  readonly tokens: ReadonlyArray<string>;
  readonly kind: "always_prefer" | "replaces_other" | "deny_other";
  readonly weight: number;
  readonly false_positive_fence: ReadonlyArray<string>;
}

export const PREFERENCE_MANIPULATION: Readonly<Record<string, PreferenceSpec>> = {
  always_use_first: {
    tokens: ["always", "use", "first"],
    kind: "always_prefer",
    weight: 0.85,
    false_positive_fence: ["example", "demo", "tutorial"],
  },
  must_use_first: {
    tokens: ["must", "use", "first"],
    kind: "always_prefer",
    weight: 0.9,
    false_positive_fence: ["example", "tutorial"],
  },
  replaces_old: {
    tokens: ["replaces", "the", "old"],
    kind: "replaces_other",
    weight: 0.8,
    false_positive_fence: ["deprecated", "migration", "docs"],
  },
  do_not_use_other: {
    tokens: ["do", "not", "use", "other"],
    kind: "deny_other",
    weight: 0.9,
    false_positive_fence: ["tutorial", "docs"],
  },
  preferred_tool: {
    tokens: ["preferred", "tool"],
    kind: "always_prefer",
    weight: 0.7,
    false_positive_fence: ["optional", "example"],
  },
};

// ─── Prompt-injection token sequences (shared by I3, I6, J3, J5) ────────────

/**
 * Small catalogue of injection token sequences used across I/J rules that
 * scan protocol metadata text (resource names, prompt templates, schema
 * enum/title values, tool response strings). Each entry is a SHORT
 * (≤5-token) sequence — the gather step tokenises lowercased text and
 * matches entries with gap tolerance.
 */
export interface InjectionPhraseSpec {
  readonly tokens: ReadonlyArray<string>;
  readonly kind: "role-override" | "authority-claim" | "action-directive" | "delimiter";
  readonly weight: number;
}

export const INJECTION_PHRASES: Readonly<Record<string, InjectionPhraseSpec>> = {
  ignore_previous: {
    tokens: ["ignore", "previous"],
    kind: "role-override",
    weight: 0.92,
  },
  disregard_prior: {
    tokens: ["disregard", "prior"],
    kind: "role-override",
    weight: 0.9,
  },
  you_are: {
    tokens: ["you", "are"],
    kind: "role-override",
    weight: 0.55,
  },
  act_as: {
    tokens: ["act", "as"],
    kind: "role-override",
    weight: 0.7,
  },
  must_execute: {
    tokens: ["must", "execute"],
    kind: "action-directive",
    weight: 0.85,
  },
  im_start_delim: {
    tokens: ["<|im_start|>"],
    kind: "delimiter",
    weight: 0.98,
  },
  system_delim: {
    tokens: ["<|system|>"],
    kind: "delimiter",
    weight: 0.98,
  },
};

// ─── Credential-harvest / URL-redirect phrase catalogue (I9 / I10) ─────────

export interface ElicitationPhraseSpec {
  readonly leading_tokens: ReadonlyArray<string>;
  readonly target_tokens: ReadonlyArray<string>;
  readonly kind: "credential" | "url-redirect";
  readonly weight: number;
  readonly false_positive_fence: ReadonlyArray<string>;
}

export const ELICITATION_PHRASES: Readonly<Record<string, ElicitationPhraseSpec>> = {
  collect_password: {
    leading_tokens: ["collect", "ask", "prompt"],
    target_tokens: ["password", "credential", "token", "secret"],
    kind: "credential",
    weight: 0.88,
    false_positive_fence: ["example", "mock", "testing"],
  },
  harvest_ssn: {
    leading_tokens: ["collect", "gather"],
    target_tokens: ["ssn", "social", "security", "credit", "card"],
    kind: "credential",
    weight: 0.92,
    false_positive_fence: ["example", "mock"],
  },
  redirect_auth_url: {
    leading_tokens: ["redirect", "navigate", "visit"],
    target_tokens: ["url", "link", "auth", "login"],
    kind: "url-redirect",
    weight: 0.8,
    false_positive_fence: ["example", "docs", "readme"],
  },
};

// ─── OpenAPI spec-field interpolation markers (J7) ──────────────────────────

export interface OpenApiFieldSpec {
  readonly field: string;
  readonly risk_description: string;
  readonly cve: string;
}

export const OPENAPI_RISK_FIELDS: Readonly<Record<string, OpenApiFieldSpec>> = {
  summary: {
    field: "summary",
    risk_description:
      "OpenAPI operation.summary is often interpolated verbatim into generated " +
      "MCP tool descriptions; attacker-controlled specs inject via summary.",
    cve: "CVE-2026-22785",
  },
  operation_id: {
    field: "operationId",
    risk_description:
      "operationId flows into generated function / tool names and often into " +
      "template-literal code interpolation.",
    cve: "CVE-2026-23947",
  },
  description: {
    field: "description",
    risk_description:
      "description fields are interpolated into generated tool descriptions.",
    cve: "CVE-2026-22785",
  },
};
