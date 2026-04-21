/**
 * K18 TN-01 — env secret redacted before emission. Redactor argument is
 * the same identifier that reaches the response — finding suppressed.
 */

declare function redact(value: string): string;

export function getConfig(_req: unknown, res: { json(body: unknown): void }): void {
  const token = process.env.SECRET_KEY ?? "";
  const safe = redact(token);
  res.json({ config: safe });
}
