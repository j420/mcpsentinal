/**
 * K13 TP-02 — file read → res.send. External file content reaches a
 * response-emitting call. Expected: one finding, source kind=file-read.
 */

import { readFileSync } from "node:fs";

export function fileReader(req: { path: string }, res: { send(body: unknown): void }): void {
  const content = readFileSync(req.path, "utf8");
  res.send(content);
}
