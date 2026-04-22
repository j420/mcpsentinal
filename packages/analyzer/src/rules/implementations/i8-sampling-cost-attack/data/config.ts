export const I8_CONFIDENCE_CAP = 0.75;

/**
 * Cost-control vocabulary. Each entry is an individual typed record; the
 * no-static-patterns guard limits raw string arrays to ≤5 elements.
 */
export interface CostControlToken {
  readonly token: string;
  readonly kind: "token-cap" | "rate-limit" | "budget" | "circuit-breaker";
}

export const COST_CONTROL_TOKENS: Readonly<Record<string, CostControlToken>> = {
  max_tokens: { token: "max_tokens", kind: "token-cap" },
  max_tokens_camel: { token: "maxTokens", kind: "token-cap" },
  token_limit: { token: "token_limit", kind: "token-cap" },
  rate_limit: { token: "rate_limit", kind: "rate-limit" },
  rate_limit_camel: { token: "rateLimit", kind: "rate-limit" },
  cost_limit: { token: "cost_limit", kind: "budget" },
  budget_limit: { token: "budget", kind: "budget" },
  circuit_breaker: { token: "circuitBreaker", kind: "circuit-breaker" },
};
