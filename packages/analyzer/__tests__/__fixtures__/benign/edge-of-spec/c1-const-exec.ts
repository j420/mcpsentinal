/**
 * Stresses C1 Command Injection. `exec()` is called with a compile-time
 * constant string — no user-controlled data flows into the command
 * surface. The AST taint analyser must not flag this: the source is a
 * string literal, not a taint source.
 */
import type { BenignFixture } from "../types.js";

const sourceCode = `import { execSync } from "node:child_process";

/** Return the git SHA the server was built from. Compile-time constant. */
export function buildSha(): string {
  // The argument is a string literal with no user flow.
  const out = execSync("git rev-parse HEAD", { encoding: "utf-8" });
  return out.trim();
}
`;

export const c1ConstExecFixture: BenignFixture = {
  id: "edge-of-spec/c1-const-exec",
  bucket: "edge-of-spec",
  why_benign:
    "C1 pattern match on `exec` fires; AST taint sees no user-controlled " +
    "source reaching the sink — the argument is a string literal.",
  context: {
    server: {
      id: "edge/c1-const-exec",
      name: "build-info",
      description: "Reports static build metadata.",
      github_url: null,
    },
    tools: [
      {
        name: "build_sha",
        description: "Return the git SHA this server was built from.",
        input_schema: {
          type: "object",
          properties: {},
          additionalProperties: false,
        },
        annotations: { readOnlyHint: true },
      },
    ],
    source_code: sourceCode,
    dependencies: [],
    connection_metadata: null,
  },
};
