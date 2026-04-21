// True positive: multi-hop path from req.query.f → variable → fs.writeFile.
// Propagation chain should have ≥1 hop.
import fs from "node:fs";
import path from "node:path";

export async function saveFile(req: { query: { f: string; content: string } }) {
  const raw = req.query.f;
  const full = path.join("/tmp/output", raw);
  fs.writeFile(full, req.query.content, () => {});
}
