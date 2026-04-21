/**
 * K6 TP-02 — admin scope embedded in an array-valued property, colon-
 * suffix admin-segment detection via structural check (`admin:org`),
 * AND a broad-prefixed token (`read:all`) — three scope classifications
 * in one finding.
 */

export const request = {
  client_id: "mcp",
  response_type: "code",
  scopes: ["read:user", "admin:org", "read:all"],
  authorization_endpoint: "https://example.com/auth",
};
