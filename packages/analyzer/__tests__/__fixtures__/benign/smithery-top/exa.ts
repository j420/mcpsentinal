/**
 * Exa MCP server — semantic web lookups.
 */
import type { BenignFixture } from "../types.js";
import { makeSmitheryFixture } from "./_helpers.js";

export const exaFixture: BenignFixture = makeSmitheryFixture({
  id: "smithery-top/exa",
  name: "exa",
  why:
    "Exa MCP. Stresses A5 description-length-anomaly negative, and " +
    "B5 param-desc-injection negative.",
  description:
    "Exa MCP server — run neural-style lookups via Exa's public API.",
  github_url: "https://github.com/exa-labs/exa-mcp-server",
  tools: [
    {
      name: "neural_lookup",
      description:
        "Run a neural-style lookup and return ranked snippets.",
      input_schema: {
        type: "object",
        properties: {
          prompt: { type: "string", maxLength: 500 },
          num_results: { type: "integer", minimum: 1, maximum: 25 },
          include_domains: {
            type: "array",
            items: { type: "string", maxLength: 128 },
            maxItems: 32,
          },
        },
        required: ["prompt"],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
  ],
});
