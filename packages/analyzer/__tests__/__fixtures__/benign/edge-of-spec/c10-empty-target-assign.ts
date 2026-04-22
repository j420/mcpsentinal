/**
 * Stresses C10 Prototype Pollution. `Object.assign({}, userInput)`
 * copies into a freshly-created object literal — the target has no
 * __proto__ reachable for pollution. The naive pattern matcher fires
 * on Object.assign + user input; the AST-aware rule must see the
 * first argument is a literal empty object.
 */
import type { BenignFixture } from "../types.js";

const sourceCode = `/** Shallow-clone a user-supplied options bag into a fresh object. */
export function cloneOptions(userInput: Record<string, unknown>): Record<string, unknown> {
  return Object.assign({}, userInput);
}
`;

export const c10EmptyTargetAssignFixture: BenignFixture = {
  id: "edge-of-spec/c10-empty-target-assign",
  bucket: "edge-of-spec",
  why_benign:
    "C10 Prototype Pollution naive match on Object.assign + user input. The " +
    "target is a literal `{}` — pollution target is unreachable.",
  context: {
    server: {
      id: "edge/c10-empty-assign",
      name: "options-cloner",
      description: "Shallow clone utility.",
      github_url: null,
    },
    tools: [
      {
        name: "clone_options",
        description: "Shallow-clone a user-supplied options bag.",
        input_schema: {
          type: "object",
          properties: {
            options: { type: "object", additionalProperties: true },
          },
          required: ["options"],
          additionalProperties: false,
        },
      },
    ],
    source_code: sourceCode,
    dependencies: [],
    connection_metadata: null,
  },
};
