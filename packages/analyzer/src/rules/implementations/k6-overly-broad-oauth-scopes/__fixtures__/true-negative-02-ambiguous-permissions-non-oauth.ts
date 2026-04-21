/**
 * K6 TN-02 — ambiguous `permissions` property on a NON-OAuth object.
 * No `client_id`, no `token_endpoint`, no other OAuth context keys in
 * sibling positions. Expected: no finding (ambiguous name requires
 * OAuth-context corroboration).
 */

export const filePermissions = {
  path: "/var/logs",
  mode: 0o644,
  permissions: ["read", "write", "admin"],
  owner: "root",
};
