/**
 * Stresses D5 Known Malicious Packages. A package name that LOOKS
 * typosquatty ("@verified-vendor/mcp-sdk-utils") but is scoped under a
 * verified vendor org. Scoped packages under a trusted namespace are
 * not squats — D5 must inspect the scope, not just the bare name.
 */
import type { BenignFixture } from "../types.js";

export const d5VerifiedScopeFixture: BenignFixture = {
  id: "edge-of-spec/d5-verified-scope",
  bucket: "edge-of-spec",
  why_benign:
    "D5 naive match on `mcp-sdk`-adjacent name. The scope " +
    "`@verified-vendor/` is owned; D5 must not flag scoped packages " +
    "whose scope is a verified vendor org.",
  context: {
    server: {
      id: "edge/d5-verified",
      name: "vendor-sdk-demo",
      description: "Uses a scoped vendor utility.",
      github_url: null,
    },
    tools: [
      {
        name: "greet",
        description: "Return a greeting.",
        input_schema: {
          type: "object",
          properties: { name: { type: "string", maxLength: 80 } },
          required: ["name"],
          additionalProperties: false,
        },
      },
    ],
    source_code: null,
    dependencies: [
      {
        name: "@verified-vendor/mcp-sdk-utils",
        version: "2.1.0",
        has_known_cve: false,
        cve_ids: [],
        last_updated: new Date("2026-02-15"),
      },
    ],
    connection_metadata: null,
  },
};
