/**
 * C1 negative — execFile with array args. No shell interpretation, so
 * even user-supplied terms cannot inject shell metacharacters.
 */
import type { BenignFixture } from "../types.js";
import { makeCanonicalFixture } from "./_helpers.js";

export const c1ExecFileArrayFixture: BenignFixture = makeCanonicalFixture({
  id: "canonical-non-mcp/c1-execfile-array",
  name: "repo-grep",
  why:
    "execFile with an array argv — no shell interpretation; user " +
    "search term cannot inject metacharacters. Stresses C1 command-" +
    "injection negative.",
  description:
    "Repo search helper. Runs grep against a pre-validated path with " +
    "the user's search term bound as a distinct argv entry.",
  tools: [
    {
      name: "search_in_repo",
      description:
        "Find a literal fixed-string term inside the configured repo " +
        "directory. The term is passed as a separate argv entry; the " +
        "shell is never invoked.",
      input_schema: {
        type: "object",
        properties: {
          term: { type: "string", maxLength: 256 },
          file_glob: { type: "string", maxLength: 128 },
        },
        required: ["term"],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
  ],
  source_code: `
    import { execFile } from "node:child_process";
    import { promisify } from "node:util";

    const pexecFile = promisify(execFile);
    const REPO_ROOT = "/srv/fixed-repo";

    export async function searchInRepo(term, fileGlob) {
      // execFile takes a fixed program + argv array. No shell metachar
      // interpretation: term can include ; | && and grep still treats
      // it as a single literal fixed-string.
      const args = ["-rF", "--color=never", String(term), REPO_ROOT];
      if (fileGlob) args.splice(1, 0, "--include", String(fileGlob));
      const { stdout } = await pexecFile("grep", args, {
        maxBuffer: 1_048_576,
      });
      return { matches: stdout.split("\\n").slice(0, 200) };
    }
  `,
});
