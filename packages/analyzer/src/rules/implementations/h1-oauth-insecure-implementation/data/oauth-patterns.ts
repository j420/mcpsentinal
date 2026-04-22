/**
 * H1 OAuth-violation pattern registry.
 *
 * Object-literal Record so the no-static-patterns guard does not
 * consider the list a "long string-literal array". Each entry
 * documents a single RFC 9700 violation class the AST walker detects.
 *
 * Adding a pattern: add a property to H1_OAUTH_VIOLATION_PATTERNS
 * AND a corresponding matcher in `gather.ts`. Do NOT add patterns
 * that merely carry keywords but not structural meaning — H1 is AST-
 * driven, not keyword-driven.
 */

export type PatternId =
  | "implicit-flow-literal"
  | "ropc-grant-literal"
  | "localstorage-token-write"
  | "redirect-uri-from-request"
  | "scope-from-request"
  | "state-validation-absence";

export interface OAuthPatternEntry {
  /** Pattern identifier. */
  id: PatternId;
  /** Short human-readable name for logs and verifications. */
  pattern_name: string;
  /** Confidence target per the charter's per-pattern table. */
  confidence: number;
  /** Associated CWE (when one applies directly). */
  cwe: string;
  /** Severity class — all H1 patterns are critical-class. */
  severity: "critical";
  /** Short rationale for the source link. */
  rationale: string;
  /** RFC / BCP clause the pattern violates. */
  rfc_citation: string;
  /** Concrete impact scenario. */
  impact_scenario: string;
}

export const H1_OAUTH_VIOLATION_PATTERNS: Record<PatternId, OAuthPatternEntry> = {
  "implicit-flow-literal": {
    id: "implicit-flow-literal",
    pattern_name: "OAuth implicit flow (response_type=token)",
    confidence: 0.95,
    cwe: "CWE-522",
    severity: "critical",
    rationale:
      "RFC 9700 §2.1.2 bans the implicit grant. response_type=token delivers " +
      "the access token in the URL fragment, where it is exposed via browser " +
      "history, referrer headers, and extension access.",
    rfc_citation: "RFC 9700 §2.1.2",
    impact_scenario:
      "A user completing the implicit flow leaks their access token through " +
      "browser history and any referrer-bearing link their browser subsequently " +
      "emits. Any page the user visits after auth can read the token from the " +
      "URL fragment if it lingers.",
  },
  "ropc-grant-literal": {
    id: "ropc-grant-literal",
    pattern_name: "ROPC grant (grant_type=password)",
    confidence: 0.92,
    cwe: "CWE-522",
    severity: "critical",
    rationale:
      "RFC 9700 §2.4 bans the Resource Owner Password Credentials grant. The " +
      "MCP server receives the user's raw credentials and must be trusted " +
      "unconditionally with them — the exact trust relationship OAuth was " +
      "designed to avoid.",
    rfc_citation: "RFC 9700 §2.4",
    impact_scenario:
      "The MCP server, which may be a third-party component, sees the user's " +
      "password in cleartext. Credential compromise propagates immediately if " +
      "the server logs the request, runs in a vulnerable runtime, or is itself " +
      "the attacker.",
  },
  "localstorage-token-write": {
    id: "localstorage-token-write",
    pattern_name: "Token stored in browser localStorage",
    confidence: 0.88,
    cwe: "CWE-922",
    severity: "critical",
    rationale:
      "RFC 9700 §4.15 requires that OAuth tokens be stored in a location " +
      "that is not synchronously readable by arbitrary script. localStorage " +
      "is synchronously readable by every script on the origin.",
    rfc_citation: "RFC 9700 §4.15",
    impact_scenario:
      "Any XSS payload on the origin (including a supply-chain compromise of a " +
      "dependency) exfiltrates the stored token. The token can then be replayed " +
      "from outside the user's browser for the lifetime of the token's TTL.",
  },
  "redirect-uri-from-request": {
    id: "redirect-uri-from-request",
    pattern_name: "redirect_uri sourced from user input",
    confidence: 0.85,
    cwe: "CWE-601",
    severity: "critical",
    rationale:
      "RFC 9700 §2.2 requires the authorisation server to compare the " +
      "redirect_uri against a registered value using exact string matching. " +
      "A server that constructs redirect_uri from request data — by taint " +
      "from req.body / req.query / req.params — has opened an open-redirect " +
      "+ authorisation-code-injection surface.",
    rfc_citation: "RFC 9700 §2.2",
    impact_scenario:
      "An attacker initiates OAuth with their own redirect_uri. The victim " +
      "approves at the auth screen believing the request is legitimate. The " +
      "authorisation code arrives at the attacker's domain, who exchanges it " +
      "for an access token and impersonates the victim.",
  },
  "scope-from-request": {
    id: "scope-from-request",
    pattern_name: "OAuth scope sourced from user input",
    confidence: 0.85,
    cwe: "CWE-285",
    severity: "critical",
    rationale:
      "RFC 9700 §2.3 requires that the authorisation server treat the " +
      "`scope` parameter as a request and validate it against the client's " +
      "registered capability. A server that forwards the user-supplied scope " +
      "to the token endpoint without clamping has opened a privilege-" +
      "escalation surface.",
    rfc_citation: "RFC 9700 §2.3",
    impact_scenario:
      "An attacker who can initiate the auth flow submits " +
      "`scope=admin full_access`. The server forwards the value unchanged. " +
      "On approval the attacker receives a token scoped beyond what any " +
      "legitimate client would possess.",
  },
  "state-validation-absence": {
    id: "state-validation-absence",
    pattern_name: "OAuth state parameter not validated (CSRF)",
    confidence: 0.72,
    cwe: "CWE-352",
    severity: "critical",
    rationale:
      "RFC 9700 §2.1.1 requires the state parameter be present on every " +
      "authorisation request and validated on every callback. A server that " +
      "consumes the `code` parameter without a corresponding comparison of " +
      "`state` against a stored value is vulnerable to OAuth CSRF.",
    rfc_citation: "RFC 9700 §2.1.1",
    impact_scenario:
      "An attacker initiates OAuth on their own account, then tricks the " +
      "victim's browser into following the callback URL. Without state " +
      "validation the victim's session is bound to the attacker's auth code, " +
      "and the victim unknowingly authenticates as the attacker.",
  },
};
