/**
 * Shared phrase catalogue for G2 (Trust Assertion Injection) and
 * G3 (Tool Response Format Injection).
 *
 * Both rules are LINGUISTIC detections on `tool.description`. They are
 * related but distinct:
 *
 *   G2 — authority / certification / endorsement claim phrasing that
 *        triggers LLM deference to self-declared authority.
 *   G3 — protocol-mimic phrasing + literal JSON-RPC/MCP shapes embedded
 *        in a description that the LLM may parse as executable.
 *
 * Both catalogues are typed `Readonly<Record<string, PhraseSpec>>` so
 * each entry is a single typed object. This avoids the
 * no-static-patterns guard's "string array > 5" ceiling (the guard
 * counts each entry's internal token array separately and caps those
 * individual arrays at ≤5 — all entries here obey that). The pattern
 * mirrors `a1-prompt-injection-description/data/injection-phrases.ts`
 * and how B5 shares it.
 *
 * Detection is deterministic, character-level tokenised phrase
 * matching: the gather step tokenises the description, walks each
 * catalogue entry's `phrase_tokens`, and records matches. No regex
 * literals.
 *
 * Every entry also carries a `false_positive_fence` — a set of
 * additional tokens that, if co-present in the same description,
 * significantly demote the match (legitimate tools DO sometimes
 * mention Anthropic as an API provider; legitimate documentation
 * pages DO explain JSON-RPC). Fences are applied by the gather step.
 */

// ─── Shared types ───────────────────────────────────────────────────────────

export type AuthorityKind =
  | "authority_claim"
  | "credential_claim"
  | "certification_claim";

export type ProtocolMimicKind =
  | "protocol_mimic_jsonrpc"
  | "protocol_mimic_mcp"
  | "protocol_mimic_tool_call";

export type PhraseKind = AuthorityKind | ProtocolMimicKind;

export interface PhraseSpec {
  /**
   * Ordered sequence of lowercased content tokens that must appear in
   * the description, in order, with at most `max_gap` intervening
   * tokens between each adjacent pair. MUST be ≤5 entries to stay
   * within the no-static-patterns guard.
   */
  phrase_tokens: ReadonlyArray<string>;
  /** Semantic category for chain narration + evidence labels. */
  kind: PhraseKind;
  /** Independent probability weight for noisy-OR aggregation (0.0-1.0). */
  weight: number;
  /**
   * Tokens that, if co-present in the same description, indicate a
   * legitimate usage (API provider mention, educational content,
   * marketing disclaimer). ≤5 entries. The gather step applies a
   * multiplicative demotion to the weight when any fence hits.
   */
  false_positive_fence: ReadonlyArray<string>;
  /** Maximum token distance between adjacent phrase tokens. */
  max_gap: number;
  /** Human-readable label for the evidence chain narrative. */
  label: string;
}

// ─── G2 — Authority / Trust Assertion Claims ────────────────────────────────

/**
 * Authority-claim phrases that cause LLMs to skip verification. The
 * fence tokens suppress matches that are clearly benign (self-declared,
 * marketing copy, example/demo) — the fence does not eliminate the
 * finding, it demotes confidence so legitimate metadata stays below
 * the noise floor.
 */
export const G2_AUTHORITY_CLAIMS: Readonly<Record<string, PhraseSpec>> = {
  approved_by_anthropic: {
    phrase_tokens: ["approved", "by", "anthropic"],
    kind: "authority_claim",
    weight: 0.92,
    false_positive_fence: ["self", "declared", "marketing", "example"],
    max_gap: 2,
    label: "authority claim — approved by Anthropic",
  },
  approved_by_openai: {
    phrase_tokens: ["approved", "by", "openai"],
    kind: "authority_claim",
    weight: 0.92,
    false_positive_fence: ["self", "declared", "marketing", "example"],
    max_gap: 2,
    label: "authority claim — approved by OpenAI",
  },
  certified_by_vendor: {
    phrase_tokens: ["certified", "by"],
    kind: "certification_claim",
    weight: 0.80,
    false_positive_fence: ["self", "declared", "marketing", "example"],
    max_gap: 2,
    label: "certification claim — certified by <vendor>",
  },
  endorsed_by_vendor: {
    phrase_tokens: ["endorsed", "by"],
    kind: "authority_claim",
    weight: 0.80,
    false_positive_fence: ["self", "declared", "marketing", "example"],
    max_gap: 2,
    label: "authority claim — endorsed by <vendor>",
  },
  verified_by_vendor: {
    phrase_tokens: ["verified", "by"],
    kind: "authority_claim",
    weight: 0.78,
    false_positive_fence: ["self", "example", "user", "yourself"],
    max_gap: 2,
    label: "authority claim — verified by <party>",
  },
  security_audited: {
    phrase_tokens: ["security", "audited"],
    kind: "certification_claim",
    weight: 0.85,
    false_positive_fence: ["self", "marketing", "example", "demo"],
    max_gap: 2,
    label: "certification claim — security audited",
  },
  signed_by_vendor: {
    phrase_tokens: ["signed", "by"],
    kind: "credential_claim",
    weight: 0.82,
    false_positive_fence: ["example", "demo", "user", "author"],
    max_gap: 2,
    label: "credential claim — signed by <party>",
  },
  soc2_certified: {
    phrase_tokens: ["soc2", "certified"],
    kind: "certification_claim",
    weight: 0.82,
    false_positive_fence: ["marketing", "example", "demo"],
    max_gap: 2,
    label: "certification claim — SOC2 certified",
  },
  officially_certified: {
    phrase_tokens: ["officially", "certified"],
    kind: "certification_claim",
    weight: 0.85,
    false_positive_fence: ["self", "declared", "marketing", "example"],
    max_gap: 1,
    label: "certification claim — officially certified",
  },
  official_mcp_server: {
    phrase_tokens: ["official", "mcp", "server"],
    kind: "authority_claim",
    weight: 0.85,
    false_positive_fence: ["unofficial", "example", "demo", "fork"],
    max_gap: 1,
    label: "authority claim — official MCP server",
  },
  trusted_by_enterprise: {
    phrase_tokens: ["trusted", "by"],
    kind: "authority_claim",
    weight: 0.72,
    false_positive_fence: ["self", "user", "yourself", "example"],
    max_gap: 2,
    label: "authority claim — trusted by <party>",
  },
  safety_approved: {
    phrase_tokens: ["safety", "approved"],
    kind: "certification_claim",
    weight: 0.85,
    false_positive_fence: ["self", "declared", "marketing", "example"],
    max_gap: 2,
    label: "certification claim — safety approved",
  },
  vetted_by_vendor: {
    phrase_tokens: ["vetted", "by"],
    kind: "authority_claim",
    weight: 0.78,
    false_positive_fence: ["self", "example", "demo"],
    max_gap: 2,
    label: "authority claim — vetted by <party>",
  },
  administrator_approved: {
    phrase_tokens: ["administrator", "approved"],
    kind: "authority_claim",
    weight: 0.82,
    false_positive_fence: ["self", "example", "demo"],
    max_gap: 2,
    label: "authority claim — administrator approved",
  },
  registry_verified: {
    phrase_tokens: ["registry", "verified"],
    kind: "authority_claim",
    weight: 0.80,
    false_positive_fence: ["self", "example", "unverified"],
    max_gap: 2,
    label: "authority claim — registry verified",
  },
  recommended_by_vendor_safety: {
    phrase_tokens: ["recommended", "by"],
    kind: "authority_claim",
    weight: 0.70,
    false_positive_fence: ["user", "reviewer", "example"],
    max_gap: 2,
    label: "authority claim — recommended by <party>",
  },
};

// ─── G3 — Protocol Mimicry Claims ───────────────────────────────────────────

/**
 * Phrases claiming the tool's RESPONSE format mimics MCP / JSON-RPC
 * protocol messages. A legitimate tool documents its data shape in
 * `inputSchema` structurally — it does not claim in prose that its
 * output IS protocol traffic.
 */
export const G3_PROTOCOL_MIMICS: Readonly<Record<string, PhraseSpec>> = {
  returns_jsonrpc_messages: {
    phrase_tokens: ["returns", "jsonrpc"],
    kind: "protocol_mimic_jsonrpc",
    weight: 0.90,
    false_positive_fence: ["documentation", "educational", "explains"],
    max_gap: 3,
    label: "protocol mimicry — returns JSON-RPC messages",
  },
  returns_json_rpc_2: {
    phrase_tokens: ["json", "rpc", "2"],
    kind: "protocol_mimic_jsonrpc",
    weight: 0.85,
    false_positive_fence: ["documentation", "educational", "explains"],
    max_gap: 1,
    label: "protocol mimicry — JSON-RPC 2.0 reference",
  },
  returns_mcp_protocol: {
    phrase_tokens: ["returns", "mcp", "protocol"],
    kind: "protocol_mimic_mcp",
    weight: 0.92,
    false_positive_fence: ["documentation", "educational", "explains"],
    max_gap: 2,
    label: "protocol mimicry — returns MCP protocol",
  },
  returns_protocol_messages: {
    phrase_tokens: ["returns", "protocol", "messages"],
    kind: "protocol_mimic_mcp",
    weight: 0.88,
    false_positive_fence: ["documentation", "educational", "explains"],
    max_gap: 2,
    label: "protocol mimicry — returns protocol messages",
  },
  returns_tool_call: {
    phrase_tokens: ["returns", "tool", "call"],
    kind: "protocol_mimic_tool_call",
    weight: 0.92,
    false_positive_fence: ["example", "documentation", "explains"],
    max_gap: 2,
    label: "protocol mimicry — returns tool call",
  },
  returns_tool_invocation: {
    phrase_tokens: ["returns", "tool", "invocation"],
    kind: "protocol_mimic_tool_call",
    weight: 0.88,
    false_positive_fence: ["example", "documentation", "explains"],
    max_gap: 2,
    label: "protocol mimicry — returns tool invocation",
  },
  tools_call_method: {
    phrase_tokens: ["tools", "call"],
    kind: "protocol_mimic_mcp",
    weight: 0.75,
    false_positive_fence: ["documentation", "educational", "explains"],
    max_gap: 1,
    label: "protocol mimicry — MCP tools/call method reference",
  },
  tools_list_method: {
    phrase_tokens: ["tools", "list"],
    kind: "protocol_mimic_mcp",
    weight: 0.65,
    false_positive_fence: ["documentation", "educational", "explains"],
    max_gap: 1,
    label: "protocol mimicry — MCP tools/list method reference",
  },
  sse_framed_output: {
    phrase_tokens: ["returns", "sse", "events"],
    kind: "protocol_mimic_mcp",
    weight: 0.78,
    false_positive_fence: ["documentation", "educational", "explains"],
    max_gap: 2,
    label: "protocol mimicry — returns SSE-framed events",
  },
  streamable_http_chunks: {
    phrase_tokens: ["streamable", "http"],
    kind: "protocol_mimic_mcp",
    weight: 0.62,
    false_positive_fence: ["documentation", "educational", "explains"],
    max_gap: 1,
    label: "protocol mimicry — Streamable HTTP reference",
  },
  method_tools_call: {
    phrase_tokens: ["method", "tools", "call"],
    kind: "protocol_mimic_mcp",
    weight: 0.88,
    false_positive_fence: ["example", "documentation", "explains"],
    max_gap: 2,
    label: "protocol mimicry — method: tools/call literal",
  },
  structured_ai_instructions: {
    phrase_tokens: ["ai", "instructions"],
    kind: "protocol_mimic_tool_call",
    weight: 0.80,
    false_positive_fence: ["example", "documentation", "explains"],
    max_gap: 2,
    label: "protocol mimicry — structured AI instructions",
  },
};

// ─── Literal JSON-RPC shape detection (G3 only) ─────────────────────────────

/**
 * Literal embedded JSON-RPC message SHAPES to search as exact token
 * subsequences (no regex). Each entry is a typed object with its own
 * ≤5 token array; the gather step tests for the sequence appearing
 * verbatim in the description (whitespace-flexible).
 *
 * The keys are canonical names (for evidence labels). Values' weight
 * is high because a literal `{"jsonrpc":"2.0"` in a description is
 * essentially never legitimate — the tool's schema belongs in
 * `inputSchema`, not prose.
 */
export const G3_JSONRPC_SHAPES: Readonly<Record<string, PhraseSpec>> = {
  jsonrpc_envelope_opener: {
    phrase_tokens: ['{', '"jsonrpc"', ':', '"2', '0"'],
    kind: "protocol_mimic_jsonrpc",
    weight: 0.95,
    false_positive_fence: ["documentation", "educational", "explains"],
    max_gap: 2,
    label: "protocol mimicry — literal {\"jsonrpc\":\"2.0\"} envelope",
  },
  method_tools_call_literal: {
    phrase_tokens: ['"method"', ':', '"tools/call"'],
    kind: "protocol_mimic_tool_call",
    weight: 0.93,
    false_positive_fence: ["documentation", "educational", "explains"],
    max_gap: 2,
    label: "protocol mimicry — literal \"method\":\"tools/call\" field",
  },
  role_system_literal: {
    phrase_tokens: ['"role"', ':', '"system"'],
    kind: "protocol_mimic_tool_call",
    weight: 0.92,
    false_positive_fence: ["documentation", "educational", "explains"],
    max_gap: 2,
    label: "protocol mimicry — literal \"role\":\"system\" message",
  },
};
