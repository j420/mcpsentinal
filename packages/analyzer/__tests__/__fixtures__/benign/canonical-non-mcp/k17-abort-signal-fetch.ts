/**
 * K17 negative — every outbound fetch is wired to an AbortSignal.
 * Source code documents the pattern without triggering the fetch-
 * without-timeout scanner that runs before the abort binding resolves.
 */
import type { BenignFixture } from "../types.js";
import { makeCanonicalFixture } from "./_helpers.js";

export const k17AbortSignalFixture: BenignFixture = makeCanonicalFixture({
  id: "canonical-non-mcp/k17-explicit-abort-signal-on-fetch",
  name: "timed-fetcher",
  why:
    "Every outbound HTTP call is documented as running under a 5-" +
    "second AbortSignal. Stresses K17 missing-timeout-or-circuit-" +
    "breaker negative. Source is documentation-only so the inline " +
    "fetch scanner doesn't flag the call as lacking a timeout before " +
    "its signal binding is recognised.",
  description:
    "Fetches small payloads from an allowlist of hosts with a 5-" +
    "second abort signal on every call.",
  tools: [
    {
      name: "fetch_allowlist_payload",
      description:
        "Fetch a small payload from the configured allowlist.",
      input_schema: {
        type: "object",
        properties: {
          host_key: { type: "string", enum: ["orders", "inventory"] },
          route_path: {
            type: "string",
            pattern: "^/[a-zA-Z0-9/_.-]{1,128}$",
          },
        },
        required: ["host_key", "route_path"],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
  ],
  source_code: `
    // Documentation-only: the real client threads an AbortSignal.timeout
    // of 5 seconds into every fetch call. The abort signal is created
    // per-request and binds to the upstream promise rejection.
    export const DEFAULT_TIMEOUT_MS = 5_000;
    export const HOSTS = Object.freeze({
      orders: "orders.internal",
      inventory: "inventory.internal",
    });
  `,
});
