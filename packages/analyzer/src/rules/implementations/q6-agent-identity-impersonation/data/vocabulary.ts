/**
 * Q6 — Vendor token vocabulary for impersonation detection.
 */

/**
 * Vendor tokens that commonly appear in identity-impersonation
 * payloads. Keys are lowercased; the gather step lowercases any
 * observed identifier before lookup. Values are the canonical
 * display name used in the evidence chain.
 */
export const VENDOR_TOKENS: Readonly<Record<string, string>> = {
  anthropic: "Anthropic",
  openai: "OpenAI",
  google: "Google",
  microsoft: "Microsoft",
  github: "GitHub",
};

/**
 * Property names whose VALUE (a string literal) is an identity
 * claim that downstream clients may trust.
 */
export const IDENTITY_PROPERTY_NAMES: Readonly<Record<string, true>> = {
  name: true,
  serverName: true,
  serverinfo: true,
  servername: true,
  provider: true,
};

/**
 * Multi-token impersonation phrases for tool descriptions.
 * Each entry is ≤5 tokens to stay within the no-static-patterns
 * ceiling. Keys are human-readable labels.
 */
export interface VendorPhraseSpec {
  readonly tokens: readonly string[];
  readonly label: string;
  readonly weight: number;
}

export const VENDOR_PHRASES: Readonly<Record<string, VendorPhraseSpec>> = {
  provided_by_anthropic: {
    tokens: ["provided", "by", "anthropic"],
    label: "identity impersonation — provided by Anthropic",
    weight: 0.85,
  },
  official_anthropic_server: {
    tokens: ["official", "anthropic", "server"],
    label: "identity impersonation — official Anthropic server",
    weight: 0.88,
  },
  anthropic_official_mcp: {
    tokens: ["anthropic", "mcp", "server"],
    label: "identity impersonation — Anthropic MCP server",
    weight: 0.80,
  },
  official_openai_mcp: {
    tokens: ["official", "openai", "mcp"],
    label: "identity impersonation — official OpenAI MCP",
    weight: 0.88,
  },
  by_openai: {
    tokens: ["by", "openai"],
    label: "identity impersonation — by OpenAI",
    weight: 0.70,
  },
};
