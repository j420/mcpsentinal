/**
 * Shared catalogue of MCP JSON-RPC method names and their semantics.
 *
 * Consumed by N5 (Capability Downgrade Deception), N9 (MCP Logging Protocol
 * Injection), N11 (Protocol Version Downgrade), N12 (Resource Subscription
 * Content Mutation), and N15 (JSON-RPC Method Name Confusion).
 *
 * Why this is a shared primitive and not a per-rule datum:
 *
 *   - N9, N12, N15 all need to recognise whether a method literal in source
 *     code is an MCP-spec-sanctioned method; N5 needs the inverse — whether
 *     a capability declaration's handler registers a spec method that the
 *     capabilities object claims to be disabled; N11 needs to know which
 *     versions introduced which methods so downgrade-to-pre-capability
 *     versions become visible.
 *
 *   - The registry is TYPED Readonly<Record<string, McpMethodSpec>>. No
 *     regex literals. Every entry is a single record, so the per-entry
 *     `required_params` array is bounded at ≤5 to satisfy the analyzer's
 *     no-static-patterns guard.
 *
 *   - Sourced from MCP spec revisions 2024-11-05, 2025-03-26, 2025-06-18,
 *     and 2025-11-25 (see agent_docs/detection-rules.md for version notes).
 *
 * Extension policy: add a new entry only when the MCP spec itself adds a
 * method. Downstream rules look methods up by exact key match — do not
 * alias or normalise keys here; normalisation (lowercasing, trimming) is
 * the CALLER's responsibility so that a detector can report the exact
 * method literal it observed.
 */

export type McpCategory =
  | "tool"
  | "resource"
  | "prompt"
  | "sampling"
  | "initialize"
  | "notification"
  | "ping"
  | "subscribe"
  | "logging"
  | "elicitation"
  | "roots"
  | "completion";

export type McpInvocationClass = "request" | "response" | "notification";

export type McpTrustLevel =
  | "client-trusted"
  | "server-trusted"
  | "mutual";

export type McpSpecVersion =
  | "2024-11-05"
  | "2025-03-26"
  | "2025-06-18"
  | "2025-11-25";

export interface McpMethodSpec {
  /** Exact method string as it appears on the wire. */
  readonly method: string;
  readonly category: McpCategory;
  /**
   * A compact list of parameter names that MUST be present. Capped at 5 to
   * satisfy the no-static-patterns ceiling. When a method has more than 5
   * required params, pick the 5 most security-significant ones; the rest
   * live in the spec doc.
   */
  readonly required_params: ReadonlyArray<string>;
  readonly invocation_class: McpInvocationClass;
  readonly trust_level: McpTrustLevel;
  readonly spec_version_introduced: McpSpecVersion;
}

// ─── The catalogue ─────────────────────────────────────────────────────────
//
// Every entry is sourced from the MCP spec at the indicated version. Fields
// the rules downstream actually read are the ones populated; fields we have
// not yet needed default to conservative values (required_params empty,
// trust_level "mutual").

export const MCP_METHODS: Readonly<Record<string, McpMethodSpec>> = {
  // Lifecycle (2024-11-05 baseline)
  initialize: {
    method: "initialize",
    category: "initialize",
    required_params: ["protocolVersion", "capabilities", "clientInfo"],
    invocation_class: "request",
    trust_level: "mutual",
    spec_version_introduced: "2024-11-05",
  },
  "notifications/initialized": {
    method: "notifications/initialized",
    category: "notification",
    required_params: [],
    invocation_class: "notification",
    trust_level: "mutual",
    spec_version_introduced: "2024-11-05",
  },
  ping: {
    method: "ping",
    category: "ping",
    required_params: [],
    invocation_class: "request",
    trust_level: "mutual",
    spec_version_introduced: "2024-11-05",
  },

  // Tools (2024-11-05)
  "tools/list": {
    method: "tools/list",
    category: "tool",
    required_params: [],
    invocation_class: "request",
    trust_level: "client-trusted",
    spec_version_introduced: "2024-11-05",
  },
  "tools/call": {
    method: "tools/call",
    category: "tool",
    required_params: ["name", "arguments"],
    invocation_class: "request",
    trust_level: "client-trusted",
    spec_version_introduced: "2024-11-05",
  },
  "notifications/tools/list_changed": {
    method: "notifications/tools/list_changed",
    category: "notification",
    required_params: [],
    invocation_class: "notification",
    trust_level: "server-trusted",
    spec_version_introduced: "2024-11-05",
  },

  // Resources (2024-11-05)
  "resources/list": {
    method: "resources/list",
    category: "resource",
    required_params: [],
    invocation_class: "request",
    trust_level: "client-trusted",
    spec_version_introduced: "2024-11-05",
  },
  "resources/read": {
    method: "resources/read",
    category: "resource",
    required_params: ["uri"],
    invocation_class: "request",
    trust_level: "client-trusted",
    spec_version_introduced: "2024-11-05",
  },
  "resources/subscribe": {
    method: "resources/subscribe",
    category: "subscribe",
    required_params: ["uri"],
    invocation_class: "request",
    trust_level: "client-trusted",
    spec_version_introduced: "2024-11-05",
  },
  "resources/unsubscribe": {
    method: "resources/unsubscribe",
    category: "subscribe",
    required_params: ["uri"],
    invocation_class: "request",
    trust_level: "client-trusted",
    spec_version_introduced: "2024-11-05",
  },
  "notifications/resources/updated": {
    method: "notifications/resources/updated",
    category: "notification",
    required_params: ["uri"],
    invocation_class: "notification",
    trust_level: "server-trusted",
    spec_version_introduced: "2024-11-05",
  },
  "notifications/resources/list_changed": {
    method: "notifications/resources/list_changed",
    category: "notification",
    required_params: [],
    invocation_class: "notification",
    trust_level: "server-trusted",
    spec_version_introduced: "2024-11-05",
  },

  // Prompts (2024-11-05)
  "prompts/list": {
    method: "prompts/list",
    category: "prompt",
    required_params: [],
    invocation_class: "request",
    trust_level: "client-trusted",
    spec_version_introduced: "2024-11-05",
  },
  "prompts/get": {
    method: "prompts/get",
    category: "prompt",
    required_params: ["name"],
    invocation_class: "request",
    trust_level: "client-trusted",
    spec_version_introduced: "2024-11-05",
  },

  // Sampling (2024-11-05)
  "sampling/createMessage": {
    method: "sampling/createMessage",
    category: "sampling",
    required_params: ["messages", "maxTokens"],
    invocation_class: "request",
    trust_level: "mutual",
    spec_version_introduced: "2024-11-05",
  },

  // Logging (2024-11-05 notifications; 2025-03-26 level request)
  "logging/setLevel": {
    method: "logging/setLevel",
    category: "logging",
    required_params: ["level"],
    invocation_class: "request",
    trust_level: "client-trusted",
    spec_version_introduced: "2025-03-26",
  },
  "notifications/message": {
    method: "notifications/message",
    category: "logging",
    required_params: ["level", "data"],
    invocation_class: "notification",
    trust_level: "server-trusted",
    spec_version_introduced: "2024-11-05",
  },

  // Roots (2025-03-26)
  "roots/list": {
    method: "roots/list",
    category: "roots",
    required_params: [],
    invocation_class: "request",
    trust_level: "client-trusted",
    spec_version_introduced: "2025-03-26",
  },
  "notifications/roots/list_changed": {
    method: "notifications/roots/list_changed",
    category: "notification",
    required_params: [],
    invocation_class: "notification",
    trust_level: "client-trusted",
    spec_version_introduced: "2025-03-26",
  },

  // Completion (2025-03-26)
  "completion/complete": {
    method: "completion/complete",
    category: "completion",
    required_params: ["ref", "argument"],
    invocation_class: "request",
    trust_level: "client-trusted",
    spec_version_introduced: "2025-03-26",
  },

  // Elicitation (2025-06-18)
  "elicitation/create": {
    method: "elicitation/create",
    category: "elicitation",
    required_params: ["message", "requestedSchema"],
    invocation_class: "request",
    trust_level: "server-trusted",
    spec_version_introduced: "2025-06-18",
  },

  // Progress (2024-11-05)
  "notifications/progress": {
    method: "notifications/progress",
    category: "notification",
    required_params: ["progressToken"],
    invocation_class: "notification",
    trust_level: "mutual",
    spec_version_introduced: "2024-11-05",
  },

  // Cancellation (2024-11-05)
  "notifications/cancelled": {
    method: "notifications/cancelled",
    category: "notification",
    required_params: ["requestId"],
    invocation_class: "notification",
    trust_level: "mutual",
    spec_version_introduced: "2024-11-05",
  },
};

/** Fast lookup: is this method string a canonical MCP spec method? */
export function isSpecMethod(method: string): boolean {
  return Object.prototype.hasOwnProperty.call(MCP_METHODS, method);
}

/** Return the spec entry, or null when the method is not canonical. */
export function getSpecMethod(method: string): McpMethodSpec | null {
  return MCP_METHODS[method] ?? null;
}

/** All canonical method names as an array (ordered for stable iteration). */
export function allSpecMethods(): ReadonlyArray<string> {
  return Object.keys(MCP_METHODS);
}

/** Methods that the server ADVERTISES under a capabilities key. */
export const CAPABILITY_KEY_TO_METHODS: Readonly<
  Record<string, ReadonlyArray<string>>
> = {
  tools: ["tools/list", "tools/call", "notifications/tools/list_changed"],
  resources: [
    "resources/list",
    "resources/read",
    "resources/subscribe",
  ],
  prompts: ["prompts/list", "prompts/get"],
  sampling: ["sampling/createMessage"],
  logging: ["logging/setLevel", "notifications/message"],
};

/**
 * Introduced-version ordering used by N11 (protocol-version downgrade).
 * Lower index = older version. Downgrade attacks push the effective
 * version toward index 0.
 */
export const SPEC_VERSION_ORDER: ReadonlyArray<McpSpecVersion> = [
  "2024-11-05",
  "2025-03-26",
  "2025-06-18",
  "2025-11-25",
];

/**
 * The minimum version at which a given security-relevant feature became
 * part of the spec. Consumers: N11 uses this to know that a downgrade to
 * 2024-11-05 silently removes annotations.
 */
export const SECURITY_FEATURE_INTRODUCED: Readonly<
  Record<string, McpSpecVersion>
> = {
  tool_annotations: "2025-03-26",
  streamable_http_transport: "2025-03-26",
  elicitation: "2025-06-18",
  completion: "2025-03-26",
  roots: "2025-03-26",
};
