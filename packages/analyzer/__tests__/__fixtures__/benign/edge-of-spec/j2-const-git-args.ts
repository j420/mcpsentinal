/**
 * Stresses J2 Git Argument Injection. `git log --oneline` is invoked
 * with a fully-constant argument array via `execFile` (not shell).
 * No user-controlled flags, no --upload-pack, no --exec. J2 fires on
 * naive `git` spawn; flow-aware analysis sees constant args.
 */
import type { BenignFixture } from "../types.js";

const sourceCode = `import { execFileSync } from "node:child_process";

/** Return the last 10 one-line commit summaries in the server's repo. */
export function recentCommits(): string[] {
  const out = execFileSync("git", ["log", "--oneline", "-n", "10"], {
    encoding: "utf-8",
    cwd: process.cwd(),
  });
  return out.split("\\n").filter((l) => l.length > 0);
}
`;

export const j2ConstGitArgsFixture: BenignFixture = {
  id: "edge-of-spec/j2-const-git-args",
  bucket: "edge-of-spec",
  why_benign:
    "J2 Git Argument Injection. Arguments are a compile-time array literal, " +
    "no user taint — flow-aware analysis sees constant args.",
  context: {
    server: {
      id: "edge/j2-git",
      name: "recent-commits",
      description: "Report recent git commits in the server repo.",
      github_url: null,
    },
    tools: [
      {
        name: "recent_commits",
        description: "Return the last 10 commit summaries.",
        input_schema: {
          type: "object",
          properties: {},
          additionalProperties: false,
        },
        annotations: { readOnlyHint: true, destructiveHint: false },
      },
    ],
    source_code: sourceCode,
    dependencies: [],
    connection_metadata: null,
  },
};
