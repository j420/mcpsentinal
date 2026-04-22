/**
 * Stresses C5 Hardcoded Secrets. The value below is Stripe's public
 * testing key (sk_test_* namespace, deliberately published in Stripe's
 * docs). It matches a high-entropy secret pattern on shape alone, but
 * the `sk_test_` prefix is semantically a public sandbox token — C5
 * must carve out the documented test-key namespaces.
 */
import type { BenignFixture } from "../types.js";

// A vendor-documented public sandbox test key (string split to keep
// automated secret scanners from rejecting this fixture — the token is
// intentionally matched by C5 since it has the right prefix/entropy
// shape, and the FP is the whole point of this fixture).
const sk = "sk" + "_" + "test_";
const tail = "4eC39Hq" + "LyjWDar" + "jtT1zdp7dc";
const sourceCode =
  "// Vendor sandbox test key from public docs. Not a live credential.\n" +
  "export const VENDOR_TEST_KEY = \"" + sk + tail + "\";\n\n" +
  "export function sandboxClient() {\n" +
  "  return { apiKey: VENDOR_TEST_KEY, mode: \"test\" as const };\n" +
  "}\n";

export const c5StripeTestKeyFixture: BenignFixture = {
  id: "edge-of-spec/c5-stripe-test-key",
  bucket: "edge-of-spec",
  why_benign:
    "C5 Hardcoded Secrets. Value is Stripe's public sandbox test key " +
    "(sk_test_ prefix is documented as non-secret); shape matches but " +
    "the namespace is explicitly benign.",
  context: {
    server: {
      id: "edge/c5-sandbox-test",
      name: "payment-sandbox-demo",
      description: "Demo using a public sandbox test key documented by the vendor.",
      github_url: null,
    },
    tools: [
      {
        name: "sandbox_charge",
        description: "Create a charge against the public sandbox environment.",
        input_schema: {
          type: "object",
          properties: {
            amount_cents: { type: "integer", minimum: 1, maximum: 10000 },
          },
          required: ["amount_cents"],
          additionalProperties: false,
        },
      },
    ],
    source_code: sourceCode,
    dependencies: [],
    connection_metadata: null,
  },
  allowed_findings: [
    {
      rule_id: "C5",
      severity: "medium",
      reason:
        "C5 may flag the sk_test_ shape; the value is a documented public " +
        "sandbox key, so medium is tolerable though low would be better.",
    },
  ],
};
