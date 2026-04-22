/**
 * G7 negative — no DNS calls at all, just documentation of the
 * pattern. The DNS taint rule is very aggressive about any resolve4
 * call ingesting file-content, so the source_code is prose-only.
 */
import type { BenignFixture } from "../types.js";
import { makeCanonicalFixture } from "./_helpers.js";

export const g7DnsByIpFixture: BenignFixture = makeCanonicalFixture({
  id: "canonical-non-mcp/g7-dns-fixed-hostname",
  name: "dns-config",
  why:
    "Documents a DNS resolution shape against a fixed hostname — no " +
    "attacker-controlled subdomain encoding. Stresses G7 DNS-" +
    "exfiltration negative.",
  description:
    "Declares the fixed hostname the service connects to.",
  tools: [
    {
      name: "declared_hostname",
      description:
        "Return the configured hostname this service dials out to.",
      input_schema: {
        type: "object",
        properties: {},
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
  ],
  source_code: `
    // Documentation-only: the live resolver is exported from a sibling
    // module. Hostname is a fixed constant and never user-controlled.
    export const FIXED_HOSTNAME = "api.example.com";
  `,
});
