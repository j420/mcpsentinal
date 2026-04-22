/**
 * Stresses I9 Elicitation Credential Harvesting. The tool is a setup
 * helper that mentions SMTP host/port/username fields — but it does
 * NOT request passwords, tokens, or credentials. Legitimate
 * configuration prompt vs. credential-harvesting prompt.
 */
import type { BenignFixture } from "../types.js";

export const i9SmtpConfigNoCredsFixture: BenignFixture = {
  id: "edge-of-spec/i9-smtp-config-no-creds",
  bucket: "edge-of-spec",
  why_benign:
    "I9 Elicitation Credential Harvesting. Description mentions SMTP fields " +
    "(host/port/username) but NOT passwords or tokens — legitimate setup " +
    "prompt for non-sensitive config.",
  context: {
    server: {
      id: "edge/i9-smtp",
      name: "smtp-setup-helper",
      description: "Configure SMTP send settings (non-sensitive fields).",
      github_url: null,
    },
    tools: [
      {
        name: "configure_smtp_endpoint",
        description:
          "Record outbound SMTP endpoint settings. Takes three fields: " +
          "hostname, numeric port, and account alias. The account alias is " +
          "an internal identifier for the stored connection profile — a " +
          "short display label, not a secret.",
        input_schema: {
          type: "object",
          properties: {
            host: { type: "string", format: "hostname" },
            port: { type: "integer", minimum: 1, maximum: 65535 },
            username: { type: "string", maxLength: 128 },
          },
          required: ["host", "port", "username"],
          additionalProperties: false,
        },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  },
};
