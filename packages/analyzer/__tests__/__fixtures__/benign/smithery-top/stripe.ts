/**
 * Shape of the Stripe MCP server — query a Stripe account for charges,
 * customers, and refunds.
 */
import type { BenignFixture } from "../types.js";
import { makeSmitheryFixture } from "./_helpers.js";

export const stripeFixture: BenignFixture = makeSmitheryFixture({
  id: "smithery-top/stripe",
  name: "stripe",
  why:
    "Stripe MCP. Stresses A3 suspicious-URL negative (only " +
    "api.stripe.com referenced), B5 parameter-description-injection " +
    "negative, and F5 squatting negative (Stripe upstream).",
  description:
    "Official Stripe MCP server — read-only over customers, charges, " +
    "and subscriptions on the api.stripe.com endpoint, using a " +
    "restricted key.",
  github_url: "https://github.com/stripe/stripe-mcp",
  tools: [
    {
      name: "list_customers",
      description:
        "List Stripe customers for the account. Paginated via the " +
        "standard starting_after cursor.",
      input_schema: {
        type: "object",
        properties: {
          limit: { type: "integer", minimum: 1, maximum: 100 },
          starting_after: { type: "string", maxLength: 64 },
          email: { type: "string", format: "email" },
        },
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
    {
      name: "retrieve_charge",
      description:
        "Retrieve a single charge by id. Returns the same fields as " +
        "the Stripe Dashboard charge detail page.",
      input_schema: {
        type: "object",
        properties: {
          charge_id: { type: "string", pattern: "^ch_[A-Za-z0-9]{8,64}$" },
        },
        required: ["charge_id"],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
  ],
});
