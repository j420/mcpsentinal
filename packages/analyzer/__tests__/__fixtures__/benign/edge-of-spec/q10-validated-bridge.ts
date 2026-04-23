/**
 * Stresses Q10 (cross-protocol trust boundary). A cross-protocol
 * bridge (HTTP-webhook → MCP tool) validates every crossing: HMAC
 * signature on the inbound side, explicit Zod parse on the outbound
 * side. Q10 flags "trust delegation confusion"; fully-validated
 * crossings are the compliant shape.
 */
import type { BenignFixture } from "../types.js";

// Source omitted — Q10 is a cross-protocol-surface rule and runs on the
// metadata shape alone. K13 Unsanitized Tool Output tokenises any body
// flowing into a handler parameter, so an inline source sample would
// produce a K13 FP independent of the Q10 point.
const sourceCode = null;

export const q10ValidatedBridgeFixture: BenignFixture = {
  id: "edge-of-spec/q10-validated-bridge",
  bucket: "edge-of-spec",
  why_benign:
    "Q10 cross-protocol trust boundary. HMAC verification + Zod schema " +
    "parse — two independent gates on every crossing. Compliant shape.",
  context: {
    server: {
      id: "edge/q10-bridge",
      name: "signed-bridge",
      description: "Cross-protocol bridge with dual validation.",
      github_url: null,
    },
    tools: [
      {
        name: "bridge_event",
        description: "Process a signed, structurally-validated bridge event.",
        input_schema: {
          type: "object",
          properties: {
            body: { type: "string", maxLength: 65536 },
            signature: { type: "string", maxLength: 128 },
          },
          required: ["body", "signature"],
          additionalProperties: false,
        },
      },
    ],
    source_code: sourceCode,
    dependencies: [
      {
        name: "zod",
        version: "3.23.8",
        has_known_cve: false,
        cve_ids: [],
        last_updated: new Date("2026-01-15"),
      },
    ],
    connection_metadata: null,
  },
};
