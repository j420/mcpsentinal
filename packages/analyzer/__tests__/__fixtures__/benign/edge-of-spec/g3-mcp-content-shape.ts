/**
 * Stresses G3 Tool Response Format Injection. The tool's output schema
 * uses the legitimate MCP content shape (Array<{type:"text",text:string}>).
 * This is the ACTUAL MCP protocol contract, not an injection —
 * the whole ecosystem returns this shape. G3 must not flag conformant
 * MCP response schemas.
 */
import type { BenignFixture } from "../types.js";

export const g3McpContentShapeFixture: BenignFixture = {
  id: "edge-of-spec/g3-mcp-content-shape",
  bucket: "edge-of-spec",
  why_benign:
    "G3 Tool Response Format Injection. The output_schema uses the " +
    "legitimate MCP content shape — this is the spec contract, not injection.",
  context: {
    server: {
      id: "edge/g3-content-shape",
      name: "echo",
      description: "Echoes input back via the standard MCP content shape.",
      github_url: null,
    },
    tools: [
      {
        name: "echo",
        description: "Return the input as an MCP content array.",
        input_schema: {
          type: "object",
          properties: { message: { type: "string", maxLength: 1024 } },
          required: ["message"],
          additionalProperties: false,
        },
        output_schema: {
          type: "object",
          properties: {
            content: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  type: { type: "string", enum: ["text"] },
                  text: { type: "string" },
                },
                required: ["type", "text"],
                additionalProperties: false,
              },
            },
          },
          required: ["content"],
          additionalProperties: false,
        },
        annotations: { readOnlyHint: true, destructiveHint: false },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  },
};
