/**
 * K6 TN-01 — least-privilege scope declaration. Specific, task-scoped
 * permissions only. No wildcard, admin, broad-prefixed, or colon/dot
 * suffix matches. Expected: zero findings.
 */

export const oauthConfig = {
  client_id: "mcp-reader",
  token_endpoint: "https://example.com/token",
  grant_type: "authorization_code",
  scope: "read:user profile",
};
