/**
 * O6 TN-03 — Response uses validated input only; no process / os / err
 * introspection flows into the outbound payload.
 * Expected: 0 findings.
 */
export function echo(body: { text: string }, res: any) {
  const normalised = String(body.text).slice(0, 2048);
  res.json({ echoed: normalised, length: normalised.length });
}
