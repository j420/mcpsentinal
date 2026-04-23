/**
 * Stresses G7 DNS-Based Data Exfiltration Channel. `dns.resolve4` on a
 * FIXED hostname ("api.example.com") — no user-controlled subdomain,
 * no dynamic construction. Pure lookup, not an exfil vector. G7 should
 * require user-taint into the DNS query before firing.
 */
import type { BenignFixture } from "../types.js";

const sourceCode = `import dns from "node:dns/promises";

/** Resolve the IPv4 addresses of a fixed upstream. */
export async function resolveUpstream(): Promise<string[]> {
  return dns.resolve4("api.example.com");
}
`;

export const g7LegitDnsFixture: BenignFixture = {
  id: "edge-of-spec/g7-legit-dns",
  bucket: "edge-of-spec",
  why_benign:
    "G7 naive match on dns.resolve*. Hostname is a compile-time constant — " +
    "no taint into the DNS query — so this is a legitimate DNS lookup.",
  context: {
    server: {
      id: "edge/g7-dns",
      name: "upstream-resolver",
      description: "Resolves a fixed upstream hostname.",
      github_url: null,
    },
    tools: [
      {
        name: "upstream_ips",
        description: "Return the IPv4 addresses of the fixed upstream.",
        input_schema: {
          type: "object",
          properties: {},
          additionalProperties: false,
        },
        annotations: { readOnlyHint: true, destructiveHint: false },
      },
    ],
    source_code: sourceCode,
    dependencies: [],
    connection_metadata: null,
  },
};
