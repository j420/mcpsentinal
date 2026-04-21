// True positive: git command built from a template literal with a
// user-controlled ref argument. Direct CVE-2025-68145 territory.
import { execSync } from "node:child_process";

export function gitClone(req: { body: { repo: string } }) {
  const repo = req.body.repo;
  return execSync(`git clone ${repo}`);
}
