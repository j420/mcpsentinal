/**
 * Stresses C13 Server-Side Template Injection. Handlebars.compile is
 * called with a STRING LITERAL template — the user only controls the
 * data passed to the rendered function, never the template source.
 * Naive C13 matchers fire on any `Handlebars.compile` call; AST-aware
 * analysis must see the argument is a literal.
 */
import type { BenignFixture } from "../types.js";

const sourceCode = `import Handlebars from "handlebars";

const GREETING = Handlebars.compile("Hello, {{name}}! You have {{count}} messages.");

/** Render a greeting for a user-supplied name. The template is static. */
export function greet(name: string, count: number): string {
  return GREETING({ name, count });
}
`;

export const c13LiteralTemplateFixture: BenignFixture = {
  id: "edge-of-spec/c13-literal-template",
  bucket: "edge-of-spec",
  why_benign:
    "C13 SSTI naive match on Handlebars.compile. Template source is a " +
    "string literal; only the data is user-controlled — not injectable.",
  context: {
    server: {
      id: "edge/c13-handlebars",
      name: "greeter",
      description: "Handlebars-based greeting.",
      github_url: null,
    },
    tools: [
      {
        name: "greet",
        description: "Render a greeting for a user-supplied name.",
        input_schema: {
          type: "object",
          properties: {
            name: { type: "string", maxLength: 80 },
            count: { type: "integer", minimum: 0, maximum: 100000 },
          },
          required: ["name", "count"],
          additionalProperties: false,
        },
      },
    ],
    source_code: sourceCode,
    dependencies: [
      {
        name: "handlebars",
        version: "4.7.8",
        has_known_cve: false,
        cve_ids: [],
        last_updated: new Date("2026-01-20"),
      },
    ],
    connection_metadata: null,
  },
};
