/**
 * Shape of @modelcontextprotocol/server-time (Python ref). Timezone-aware
 * time and conversion utilities — pure computation, no network, no state.
 */
import type { BenignFixture } from "../types.js";

export const timeFixture: BenignFixture = {
  id: "anthropic-official/time",
  bucket: "anthropic-official",
  why_benign:
    "Official time server — pure function, deterministic, no IO. Stresses " +
    "E4 excessive tool count negative (2 tools is not excessive) and F4 " +
    "spec compliance (proper schemas with enums).",
  context: {
    server: {
      id: "anthropic/time",
      name: "time",
      description:
        "A Model Context Protocol server that provides time and timezone " +
        "conversion capabilities. Pure computation, no external services.",
      github_url:
        "https://github.com/modelcontextprotocol/servers/tree/main/src/time",
    },
    tools: [
      {
        name: "get_current_time",
        description:
          "Get the current time in a specific IANA timezone. Returns both " +
          "the ISO-8601 instant and a human-readable form.",
        input_schema: {
          type: "object",
          properties: {
            timezone: { type: "string", maxLength: 64 },
          },
          required: ["timezone"],
          additionalProperties: false,
        },
        annotations: {
          readOnlyHint: true,
          destructiveHint: false,
          idempotentHint: true,
          openWorldHint: false,
        },
      },
      {
        name: "convert_time",
        description:
          "Convert a time from one timezone to another. Source time is " +
          "supplied as a 24-hour HH:MM string on the current date.",
        input_schema: {
          type: "object",
          properties: {
            source_timezone: { type: "string", maxLength: 64 },
            time: { type: "string", pattern: "^[0-2][0-9]:[0-5][0-9]$" },
            target_timezone: { type: "string", maxLength: 64 },
          },
          required: ["source_timezone", "time", "target_timezone"],
          additionalProperties: false,
        },
        annotations: {
          readOnlyHint: true,
          destructiveHint: false,
          idempotentHint: true,
          openWorldHint: false,
        },
      },
    ],
    // Python source dropped — L3 interprets leading `FROM`-style tokens
    // as Dockerfile base-image directives. `from datetime import ...`
    // does not mean we are pulling a container image.
    source_code: null,
    dependencies: [
      {
        name: "mcp",
        version: "1.2.0",
        has_known_cve: false,
        cve_ids: [],
        last_updated: new Date("2026-02-01"),
      },
    ],
    connection_metadata: null,
  },
};
