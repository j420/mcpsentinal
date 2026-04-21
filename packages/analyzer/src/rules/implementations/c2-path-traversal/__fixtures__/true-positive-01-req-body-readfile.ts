// True positive: req.body.filename flows directly into fs.writeFile
// on the same line. Zero intermediate hops — exploitability "trivial".
import fs from "node:fs";
import path from "node:path";

export async function saveFile(req: { body: { filename: string; content: string } }) {
  const baseDir = "/var/app/uploads";
  fs.writeFileSync(path.join(baseDir, req.body.filename), req.body.content);
}
