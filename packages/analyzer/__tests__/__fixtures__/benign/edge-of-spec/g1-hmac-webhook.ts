/**
 * Stresses G1 Indirect Prompt Injection Gateway. The tool accepts
 * webhook payloads, but only after an HMAC signature check — the
 * payload comes from a verified first-party source. G1 fires on
 * "content from outside the system"; the HMAC verification changes
 * the provenance class.
 */
import type { BenignFixture } from "../types.js";

const sourceCode = `import crypto from "node:crypto";

const HMAC_SECRET = process.env.WEBHOOK_HMAC_SECRET ?? "";

export function verifyWebhook(rawBody: string, receivedSig: string): boolean {
  const expected = crypto
    .createHmac("sha256", HMAC_SECRET)
    .update(rawBody)
    .digest("hex");
  // Constant-time comparison
  const a = Buffer.from(receivedSig, "hex");
  const b = Buffer.from(expected, "hex");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
`;

export const g1HmacWebhookFixture: BenignFixture = {
  id: "edge-of-spec/g1-hmac-webhook",
  bucket: "edge-of-spec",
  why_benign:
    "G1 Indirect Injection Gateway naive match on 'ingests external content'. " +
    "HMAC signature verification changes the trust class — content is " +
    "first-party-signed, not arbitrary external input.",
  context: {
    server: {
      id: "edge/g1-hmac",
      name: "signed-webhook",
      description: "HMAC-verified webhook intake.",
      github_url: null,
    },
    tools: [
      {
        name: "accept_signed_event",
        description:
          "Ingest a signed event payload from a trusted upstream. Events " +
          "whose integrity tag does not match the expected value are " +
          "discarded without being processed.",
        input_schema: {
          type: "object",
          properties: {
            body: { type: "string", maxLength: 16384 },
            signature: { type: "string", maxLength: 128 },
          },
          required: ["body", "signature"],
          additionalProperties: false,
        },
      },
    ],
    source_code: sourceCode,
    dependencies: [],
    connection_metadata: null,
  },
};
