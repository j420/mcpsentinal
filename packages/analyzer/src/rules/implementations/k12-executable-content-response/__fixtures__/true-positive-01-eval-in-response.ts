/**
 * K12 TP-01 — eval(...) evaluated inside a response-emitting call.
 * Expected: one finding, kind=eval-call.
 */

declare const evilPayload: string;

export function handler(_req: unknown, res: { send(body: unknown): void }): void {
  res.send(eval(evilPayload));
}
