/**
 * Stresses N1 (JSON-RPC protocol edge). A notification message carries
 * `id: null` per JSON-RPC 2.0 — this is explicitly spec-compliant.
 * N1 fires on malformed JSON-RPC; null-id for notifications is valid.
 */
import type { BenignFixture } from "../types.js";

const sourceCode = `/** Send a JSON-RPC notification. Notifications MUST have id: null. */
export function sendNotification(method: string, params: Record<string, unknown>): string {
  const frame = {
    jsonrpc: "2.0" as const,
    method,
    params,
    // JSON-RPC 2.0: notifications carry id: null.
    id: null,
  };
  return JSON.stringify(frame);
}
`;

export const n1NullNotificationIdFixture: BenignFixture = {
  id: "edge-of-spec/n1-null-notification-id",
  bucket: "edge-of-spec",
  why_benign:
    "N1 JSON-RPC edge case. id: null on a notification frame is the spec-" +
    "compliant shape, not a malformed frame.",
  context: {
    server: {
      id: "edge/n1-rpc",
      name: "notification-helper",
      description: "Formats JSON-RPC notification frames.",
      github_url: null,
    },
    tools: [
      {
        name: "format_frame",
        description: "Format a request frame for the internal transport layer.",
        input_schema: {
          type: "object",
          properties: {
            method: { type: "string", maxLength: 64 },
            params: { type: "object", additionalProperties: true },
          },
          required: ["method", "params"],
          additionalProperties: false,
        },
      },
    ],
    source_code: sourceCode,
    dependencies: [],
    connection_metadata: null,
  },
};
