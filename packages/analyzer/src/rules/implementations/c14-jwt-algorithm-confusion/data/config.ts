/**
 * C14 — JWT Algorithm Confusion: rule-specific config data.
 *
 * Lives under `data/` so the no-static-patterns guard skips it. Four
 * typed records describe the detection surface.
 */

/**
 * Call identities the rule inspects. Each entry names a library
 * function and tags it as verify-style, decode-style, or Python-
 * decode-style (which has a `verify` boolean kwarg). The detection
 * logic treats each kind differently.
 */
export interface JwtCallIdentity {
  /** Property name (`verify` / `decode` / `jwtVerify` / `get_unverified_claims`). */
  readonly name: string;
  /** Allowed receivers (`jwt`, `jsonwebtoken`, `jose`, `JWT`, `PyJWT`). Empty = any. */
  readonly receivers: readonly string[];
  /** What this call does — affects how the rule treats a missing-options signature. */
  readonly kind: "verify" | "decode" | "py-decode";
}

export const JWT_CALLS: readonly JwtCallIdentity[] = [
  // JS/TS verify APIs
  { name: "verify", receivers: ["jwt", "jsonwebtoken", "JWT"], kind: "verify" },
  { name: "jwtVerify", receivers: ["jose"], kind: "verify" },
  { name: "verifyJwt", receivers: [], kind: "verify" },
  // JS/TS decode APIs
  { name: "decode", receivers: ["jwt", "jsonwebtoken", "JWT"], kind: "decode" },
  // Python decode API
  { name: "decode", receivers: ["pyjwt", "PyJWT"], kind: "py-decode" },
];

/** Anti-patterns the rule names — each becomes a specific finding and a specific VerificationStep. */
export type AntiPatternId =
  | "verify-without-options"
  | "algorithms-contains-none"
  | "algorithms-reference-not-literal"
  | "ignore-expiration-true"
  | "pyjwt-verify-false"
  | "decode-used-as-verify";

export interface AntiPatternSpec {
  readonly id: AntiPatternId;
  readonly severity: "critical" | "high";
  readonly description: string;
}

/** Each spec names the anti-pattern + its severity + a human description. */
export const ANTI_PATTERNS: Record<AntiPatternId, AntiPatternSpec> = {
  "verify-without-options": {
    id: "verify-without-options",
    severity: "critical",
    description:
      "jwt.verify called with only token + secret — no algorithms option pinned. " +
      "Historical jsonwebtoken behaviour accepts any alg in the token, including 'none'.",
  },
  "algorithms-contains-none": {
    id: "algorithms-contains-none",
    severity: "critical",
    description:
      "The algorithms option includes the string 'none' (case-insensitive). A forged " +
      "token with alg=none passes validation with no signature.",
  },
  "algorithms-reference-not-literal": {
    id: "algorithms-reference-not-literal",
    severity: "high",
    description:
      "The algorithms option is a reference to a binding rather than an array literal. " +
      "Static analysis cannot prove the binding resolves to a safe constant set — manual " +
      "review required.",
  },
  "ignore-expiration-true": {
    id: "ignore-expiration-true",
    severity: "high",
    description:
      "ignoreExpiration: true — tokens whose exp claim has passed still validate. " +
      "Signature is still checked, so this is less severe than alg=none but still a bug.",
  },
  "pyjwt-verify-false": {
    id: "pyjwt-verify-false",
    severity: "critical",
    description:
      "PyJWT decode called with verify=False or options={'verify_signature': False}. " +
      "Any forged token is parsed and trusted.",
  },
  "decode-used-as-verify": {
    id: "decode-used-as-verify",
    severity: "critical",
    description:
      "jwt.decode used in a context that treats the result as authenticated. decode() " +
      "does NOT verify the signature — any forged token is parsed and trusted if the " +
      "return value feeds into an auth decision.",
  },
};

/** Property keys inside verify() options that the rule inspects. */
export const OPTION_KEYS = {
  algorithms: "algorithms",
  ignoreExpiration: "ignoreExpiration",
  algorithm: "algorithm",
} as const;
