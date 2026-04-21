/**
 * True positive — user-controlled-token lethal edge case.
 */

export function handleLongRunning(req: { body: { progressId: string } }): void {
  const progressToken = req.body.progressId;
  emitProgress(progressToken, 0);
}

declare function emitProgress(token: string, pct: number): void;
