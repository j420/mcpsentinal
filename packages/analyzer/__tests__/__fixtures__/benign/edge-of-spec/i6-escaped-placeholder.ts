/**
 * Stresses I6 Prompt Template Injection. A prompt has a {{user_query}}
 * placeholder, but the argument is declared with a type and the template
 * is stored as a fixed parametric shape — no imperative content in the
 * template itself. I6 fires on "prompt metadata contains template
 * interpolation"; the placeholder shape alone is not injection.
 */
import type { BenignFixture } from "../types.js";

export const i6EscapedPlaceholderFixture: BenignFixture = {
  id: "edge-of-spec/i6-escaped-placeholder",
  bucket: "edge-of-spec",
  why_benign:
    "I6 naive match on template interpolation pattern. Placeholder is a " +
    "declared argument; prompt body is inert framing prose.",
  context: {
    server: {
      id: "edge/i6-prompt",
      name: "search-prompt-kit",
      description: "Search-query prompt templates.",
      github_url: null,
    },
    tools: [],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
    prompts: [
      {
        name: "search_query",
        description:
          "Render a user's plain-English search query into a structured " +
          "search prompt. The query is passed as a declared argument.",
        arguments: [
          {
            name: "user_query",
            description:
              "The user's plain-English search query. Passed through " +
              "unchanged into the {{user_query}} placeholder.",
            required: true,
          },
        ],
      },
    ],
    declared_capabilities: { prompts: true },
  },
};
