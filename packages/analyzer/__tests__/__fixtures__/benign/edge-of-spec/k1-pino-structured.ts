/**
 * Stresses K1 Absent Structured Logging. Code uses pino with a
 * well-formed structured log call — a context object (req_id, user_id)
 * + a message string. K1 fires when logging is absent or uses plain
 * string templates; structured pino is the canonical positive.
 */
import type { BenignFixture } from "../types.js";

const sourceCode = `import pino from "pino";

const logger = pino({ name: "edge-k1-fixture" });

export function handleRequest(reqId: string, userId: string, op: string) {
  logger.info({ req_id: reqId, user_id: userId, op }, "request.handled");
}
`;

export const k1PinoStructuredFixture: BenignFixture = {
  id: "edge-of-spec/k1-pino-structured",
  bucket: "edge-of-spec",
  why_benign:
    "K1 Absent Structured Logging. Code uses pino with a structured context " +
    "object — this is the canonical compliant pattern, not a finding.",
  context: {
    server: {
      id: "edge/k1-pino",
      name: "structured-logger",
      description: "Pino-based structured logging demo.",
      github_url: null,
    },
    tools: [
      {
        name: "log_event",
        description: "Log a structured event.",
        input_schema: {
          type: "object",
          properties: {
            req_id: { type: "string", format: "uuid" },
            user_id: { type: "string", format: "uuid" },
            op: { type: "string", maxLength: 64 },
          },
          required: ["req_id", "user_id", "op"],
          additionalProperties: false,
        },
      },
    ],
    source_code: sourceCode,
    dependencies: [
      {
        name: "pino",
        version: "9.5.0",
        has_known_cve: false,
        cve_ids: [],
        last_updated: new Date("2026-02-20"),
      },
    ],
    connection_metadata: null,
  },
};
