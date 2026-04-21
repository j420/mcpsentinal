// True positive: git call with an explicit --upload-pack flag embedding
// a user-controlled value — direct CVE-2025-68145 exploit primitive.
import { exec } from "node:child_process";

export function gitFetch(req: { body: { repo: string; uploadPack: string } }) {
  const repo = req.body.repo;
  const uploadPack = req.body.uploadPack;
  return exec(`git fetch --upload-pack=${uploadPack} ${repo}`);
}
