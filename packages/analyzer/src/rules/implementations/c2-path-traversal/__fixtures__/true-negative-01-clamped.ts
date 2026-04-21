// True negative: path is resolved via path.resolve with the tainted
// segment as arg 0, so the AST taint engine sees `resolve` as a
// sanitiser and drops the flow to `sanitized: true`. The charter
// records this as "mitigation present" — severity drops below critical.
import fs from "node:fs";
import path from "node:path";

export function safeWrite(req: { body: { filename: string } }) {
  const resolved = path.resolve(req.body.filename);
  fs.writeFileSync(resolved, "ok\n");
}
