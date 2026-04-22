/**
 * Tavily MCP server — AI-native lookups.
 */
import type { BenignFixture } from "../types.js";
import { makeSmitheryFixture } from "./_helpers.js";

export const tavilyFixture: BenignFixture = makeSmitheryFixture({
  id: "smithery-top/tavily",
  name: "tavily",
  why:
    "Tavily MCP. Stresses A1 prompt-injection-in-description negative " +
    "(plain intent, no role-play), and B5 param-desc-injection " +
    "negative.",
  description:
    "Tavily MCP server — run lookups and retrieve summarised results " +
    "from the Tavily HTTP API.",
  github_url: "https://github.com/tavily-ai/tavily-mcp",
  tools: [
    {
      name: "run_lookup",
      description:
        "Run a lookup. Returns a list of result objects with title, " +
        "source, snippet, and score.",
      input_schema: {
        type: "object",
        properties: {
          prompt: { type: "string", maxLength: 400 },
          search_depth: { type: "string", enum: ["basic", "advanced"] },
          max_results: { type: "integer", minimum: 1, maximum: 20 },
        },
        required: ["prompt"],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
  ],
});
