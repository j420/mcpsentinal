/**
 * K12 TN-02 — simple text response with no executable constructs.
 * Expected: no finding.
 */

export function handler(_req: unknown, res: { json(body: unknown): void }): void {
  res.json({ status: "ok", message: "Request processed" });
}
