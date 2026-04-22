/**
 * L9 negative — a tool whose shape is order submission. Source code is
 * documentation-only so runtime taint rules don't flag it for the
 * fetch pattern alone (this fixture is about the L9 secret-exfil
 * sink classification, not about runtime fetch hygiene).
 */
import type { BenignFixture } from "../types.js";
import { makeCanonicalFixture } from "./_helpers.js";

export const l9LegitFetchBodyFixture: BenignFixture = makeCanonicalFixture({
  id: "canonical-non-mcp/l9-legitimate-fetch-with-order-body",
  name: "order-submitter",
  why:
    "Order payload is ordinary business data, not credentials or " +
    "filesystem content. Stresses L9 secret-exfil negative.",
  description:
    "Submits an order to the configured order-service endpoint with " +
    "the order details in the request body.",
  tools: [
    {
      name: "submit_order",
      description:
        "Submit an order to the configured order-service endpoint.",
      input_schema: {
        type: "object",
        properties: {
          sku: { type: "string", pattern: "^[A-Z0-9-]{4,32}$" },
          quantity: { type: "integer", minimum: 1, maximum: 1000 },
          shipping_zip: { type: "string", pattern: "^[0-9]{5}$" },
        },
        required: ["sku", "quantity", "shipping_zip"],
        additionalProperties: false,
      },
    },
  ],
  source_code: `
    // Documentation-only: the real submitter POSTs the validated
    // order payload to the configured ENDPOINT. No credential
    // material flows into the body.
    export const ENDPOINT = "https://orders.example.com/v1/orders";
  `,
});
