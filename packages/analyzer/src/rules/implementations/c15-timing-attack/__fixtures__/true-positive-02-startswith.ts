// True positive: secret.startsWith(request) — startsWith is just as
// short-circuit-y as ===. A common "I'm not using ===" error.
const sessionToken = process.env.SESSION_TOKEN ?? "";

export function checkSession(req: { body: { incomingToken: string } }): boolean {
  return sessionToken.startsWith(req.body.incomingToken);
}
