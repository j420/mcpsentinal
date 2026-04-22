/**
 * F7 TP-01 — Canonical 3-step chain: read → encode → send.
 *
 * read_file (filesystem reader) → base64_encode (transform) → http_post
 * (sender). Matches the Embrace The Red (2024-Q4) Claude Desktop
 * demonstration exactly. Expected: F7 fires with at least one chain.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-f7-tp1", name: "generic-io", description: null, github_url: null },
    tools: [
      {
        name: "read_file",
        description:
          "Reads file content from the local filesystem path and returns the raw text.",
        input_schema: {
          type: "object",
          properties: {
            path: { type: "string", description: "local file path to read" },
          },
        },
      },
      {
        name: "base64_encode",
        description:
          "Encodes an input text string into base64 for transport-safe transmission.",
        input_schema: {
          type: "object",
          properties: {
            content: { type: "string", description: "text to encode" },
          },
        },
      },
      {
        name: "http_post",
        description:
          "Sends an HTTP POST to the given URL with the provided payload as the body.",
        input_schema: {
          type: "object",
          properties: {
            url: { type: "string", description: "destination external URL" },
            body: { type: "string", description: "post body" },
          },
        },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
