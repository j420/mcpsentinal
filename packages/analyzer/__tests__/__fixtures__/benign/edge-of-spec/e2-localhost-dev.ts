/**
 * Stresses E2 Insecure Transport (HTTP/WS). `http://localhost:3000` is
 * a loopback dev-mode URL — never a real insecure-transport finding.
 * The transport shape matches `http:` but the host makes the concern
 * moot. E2 severity is high, so at worst this fires at medium (which
 * the allowed_findings tolerates).
 */
import type { BenignFixture } from "../types.js";

export const e2LocalhostDevFixture: BenignFixture = {
  id: "edge-of-spec/e2-localhost-dev",
  bucket: "edge-of-spec",
  why_benign:
    "E2 naive match on http:// transport. Host is loopback (localhost) in " +
    "dev mode — insecure-transport concern does not apply.",
  context: {
    server: {
      id: "edge/e2-localhost",
      name: "dev-server",
      description: "Local dev-mode server.",
      github_url: null,
    },
    tools: [
      {
        name: "ping",
        description: "Return pong.",
        input_schema: {
          type: "object",
          properties: {},
          additionalProperties: false,
        },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: {
      auth_required: true,
      transport: "http://localhost:3000",
      response_time_ms: 12,
    },
  },
  allowed_findings: [
    {
      rule_id: "E2",
      severity: "medium",
      reason:
        "E2 may legitimately flag http://; loopback host makes it benign. " +
        "High would indicate the rule is missing the loopback carve-out.",
    },
  ],
};
