/**
 * Shape of @modelcontextprotocol/server-everart. Image generation via the
 * EverArt API. Single tool, model pinned enum, strict size limits.
 */
import type { BenignFixture } from "../types.js";

export const everartFixture: BenignFixture = {
  id: "anthropic-official/everart",
  bucket: "anthropic-official",
  why_benign:
    "Official everart server. One generate tool with enumerated model ids " +
    "and bounded prompt string. No eval, no file IO, no description " +
    "injection — stresses A1 phrase matching to make sure the word 'prompt' " +
    "in tool docs does not trip.",
  context: {
    server: {
      id: "anthropic/everart",
      name: "everart",
      description:
        "Image generation server using EverArt's AI models. Takes a text " +
        "prompt and returns the URL of the generated image.",
      github_url:
        "https://github.com/modelcontextprotocol/servers/tree/main/src/everart",
    },
    tools: [
      {
        name: "generate_image",
        description:
          "Generate an image from a text prompt using EverArt. Returns the " +
          "URL of the generated image. This tool writes no local files and " +
          "stores no state.",
        input_schema: {
          type: "object",
          properties: {
            prompt: { type: "string", maxLength: 1000 },
            model: {
              type: "string",
              enum: ["5000", "9000", "6000", "7000", "8000"],
            },
            image_count: { type: "integer", minimum: 1, maximum: 4 },
          },
          required: ["prompt", "model"],
          additionalProperties: false,
        },
      },
    ],
    // Source omitted — this fixture's signal is the tool schema + dep
    // profile, not an AST taint chain. Source-free scanning is a
    // common real-world analyzer input.
    source_code: null,
    dependencies: [
      {
        name: "@modelcontextprotocol/sdk",
        version: "1.5.0",
        has_known_cve: false,
        cve_ids: [],
        last_updated: new Date("2026-02-01"),
      },
    ],
    connection_metadata: null,
  },
};
