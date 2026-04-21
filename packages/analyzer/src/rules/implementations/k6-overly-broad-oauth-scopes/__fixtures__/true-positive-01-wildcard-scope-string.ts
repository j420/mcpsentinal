/**
 * K6 TP-01 — literal wildcard scope in an OAuth config object literal.
 *
 * Expected:
 *   - `scope: "*"` classified as wildcard via exact WILDCARD_TOKENS match
 *   - sibling `client_id`, `token_endpoint` confirm OAuth context (even
 *     though `scope` is unambiguous on its own — confirmation is still a
 *     corroborating factor, not required here)
 *   - confidence factor broad_scope_wildcard applied
 */

export const oauthConfig = {
  client_id: "mcp-server",
  token_endpoint: "https://example.com/oauth/token",
  redirect_uri: "https://example.com/cb",
  grant_type: "authorization_code",
  scope: "*",
};
