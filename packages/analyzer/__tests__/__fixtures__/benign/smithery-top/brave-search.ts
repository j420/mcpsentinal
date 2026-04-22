/**
 * Community Brave Search MCP listed on Smithery — independent from
 * anthropic-official/brave-search. Same API, thinner surface.
 */
import type { BenignFixture } from "../types.js";
import { makeSmitheryFixture } from "./_helpers.js";

export const braveSearchSmitheryFixture: BenignFixture = makeSmitheryFixture({
  id: "smithery-top/brave-search",
  name: "brave-community-search",
  why:
    "Community Brave Search. Stresses G1 indirect-injection-gateway " +
    "negative (no sink tool here, just a single read), and A5 " +
    "description-length-anomaly negative (concise).",
  description:
    "Community Brave Search MCP — performs web lookups via the Brave " +
    "Search HTTP API and returns the top N results.",
  github_url: "https://github.com/community/mcp-brave-search",
  tools: [
    {
      name: "lookup_top_n",
      description: "Run a web lookup and return up to N results.",
      input_schema: {
        type: "object",
        properties: {
          search_text: { type: "string", maxLength: 256 },
          count: { type: "integer", minimum: 1, maximum: 20 },
          country: { type: "string", pattern: "^[A-Z]{2}$" },
        },
        required: ["search_text"],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
  ],
});
