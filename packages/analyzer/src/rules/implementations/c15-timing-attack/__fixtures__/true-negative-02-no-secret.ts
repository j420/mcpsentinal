// True negative: comparison between two non-secret values. Tools may
// compare lots of strings — only secrets matter for C15.
export function isAdmin(req: { body: { role: string } }): boolean {
  return req.body.role === "admin";
}
