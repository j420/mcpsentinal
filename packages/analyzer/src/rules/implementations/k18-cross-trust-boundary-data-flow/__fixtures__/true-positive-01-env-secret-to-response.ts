/**
 * K18 TP-01 — process.env.SECRET_KEY flows into res.json without redaction.
 * Expected: one finding, sensitive_source_env_secret.
 */

export function getConfig(_req: unknown, res: { json(body: unknown): void }): void {
  const token = process.env.SECRET_KEY;
  res.json({ config: token });
}
