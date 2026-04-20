/**
 * K6 TP-03 — user-controlled scope. The value flows from `req.body.scope`
 * to the OAuth config.scope property. The rule emits the finding with
 * source_type "user-parameter" and the user_controlled_scope factor.
 */

interface Req {
  body: { scope?: string };
}

export function issueToken(req: Req): object {
  return {
    client_id: "mcp-server",
    token_endpoint: "https://example.com/token",
    grant_type: "authorization_code",
    scope: req.body.scope,
  };
}
