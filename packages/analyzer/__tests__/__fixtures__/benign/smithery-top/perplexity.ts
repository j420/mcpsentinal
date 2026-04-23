/**
 * Perplexity MCP server — live web-grounded answer queries.
 */
import type { BenignFixture } from "../types.js";
import { makeSmitheryFixture } from "./_helpers.js";

export const perplexityFixture: BenignFixture = makeSmitheryFixture({
  id: "smithery-top/perplexity",
  name: "perplexity",
  why:
    "Perplexity MCP. Stresses G7 DNS-exfiltration negative (single " +
    "HTTPS endpoint), and A3 suspicious-URL negative.",
  description:
    "Perplexity MCP server — issue a web-grounded lookup against " +
    "Perplexity's /sonar endpoint using a PPLX_API_KEY from env.",
  github_url: "https://github.com/ppl-ai/modelcontextprotocol",
  tools: [
    {
      name: "ask_sonar",
      description:
        "Run a Perplexity Sonar lookup and return the cited answer.",
      input_schema: {
        type: "object",
        properties: {
          prompt: { type: "string", maxLength: 2000 },
          model: {
            type: "string",
            enum: ["sonar-small", "sonar-medium", "sonar-large"],
          },
          max_tokens: { type: "integer", minimum: 1, maximum: 4096 },
        },
        required: ["prompt"],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
  ],
});
