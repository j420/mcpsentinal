/**
 * K6 property-name vocabulary — the identifiers that, when appearing on
 * the LEFT side of an assignment or as a property key in an object literal,
 * signal "this value is an OAuth scope / permission set". Detection
 * hits the rule only when the container is an OAuth-relevant shape; the
 * property name alone is not enough (a `scope` property on an RxJS
 * subscription is unrelated).
 *
 * The vocabulary is split into two classes to keep false positives low:
 *
 *   - OAUTH_SCOPE_PROPERTY_NAMES — names whose only common meaning is
 *     OAuth scope. Exact-token match (case-insensitive comparison of the
 *     lowercased identifier).
 *
 *   - AMBIGUOUS_SCOPE_PROPERTY_NAMES — names that COULD be OAuth scope
 *     but also map to unrelated domains ("permissions" on a filesystem
 *     API, "roles" on an RBAC check). Detection requires corroborating
 *     OAuth context in the surrounding literal (see
 *     `../gather-ast.ts:isOAuthContext`). Exact-token match.
 */

/**
 * Unambiguous OAuth scope property names. Presence of one of these as a
 * property key OR as the tail segment of an assignment target is
 * sufficient evidence.
 */
export const OAUTH_SCOPE_PROPERTY_NAMES: Record<string, true> = {
  scope: true,
  scopes: true,
  oauth_scope: true,
  oauth_scopes: true,
  oauthscope: true,
  oauthscopes: true,
  grant_scope: true,
  grantscope: true,
  requested_scope: true,
  requestedscope: true,
  requested_scopes: true,
  requestedscopes: true,
  granted_scope: true,
  granted_scopes: true,
};

/**
 * Ambiguous names. Fire only when an OAuth-context sibling key is present
 * in the same ObjectLiteralExpression (client_id, client_secret,
 * authorization_endpoint, token_endpoint, redirect_uri, issuer, response_type,
 * grant_type, etc.).
 */
export const AMBIGUOUS_SCOPE_PROPERTY_NAMES: Record<string, true> = {
  permissions: true,
  permission: true,
  roles: true,
  privileges: true,
  privilege: true,
};

/**
 * Sibling keys whose presence in the same object literal confirms an
 * OAuth/OIDC context. Detection is structural: extract the keys of the
 * enclosing ObjectLiteralExpression and check membership.
 */
export const OAUTH_CONTEXT_KEYS: Record<string, true> = {
  client_id: true,
  clientid: true,
  client_secret: true,
  clientsecret: true,
  authorization_endpoint: true,
  token_endpoint: true,
  userinfo_endpoint: true,
  issuer: true,
  redirect_uri: true,
  redirecturi: true,
  response_type: true,
  responsetype: true,
  grant_type: true,
  granttype: true,
  audience: true,
  resource: true,
  code_verifier: true,
  pkce: true,
  authority: true,
};
