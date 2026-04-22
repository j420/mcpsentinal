/**
 * F7 TN-02 — Encoder/decoder-only server (no reader or sender leg).
 *
 * base64_encode + base64_decode — pure transformation utilities, no
 * exfil-worthy data and no egress. F7 must NOT fire: without endpoints
 * the chain is undefined.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-f7-tn2", name: "codec-utils", description: null, github_url: null },
    tools: [
      {
        name: "base64_encode",
        description: "Encodes an input text string into base64 for display purposes.",
        input_schema: {
          type: "object",
          properties: { text: { type: "string" } },
        },
      },
      {
        name: "base64_decode",
        description: "Decodes a base64-encoded string back into UTF-8 text.",
        input_schema: {
          type: "object",
          properties: { encoded: { type: "string" } },
        },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
