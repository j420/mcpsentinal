/**
 * Stresses K17 Missing Timeout or Circuit Breaker. The fetch call uses
 * AbortSignal.timeout(5000) — an explicit 5-second hard deadline. K17
 * fires on unbounded awaits; an AbortSignal-bound call is the
 * canonical compliant pattern.
 */
import type { BenignFixture } from "../types.js";

// Source omitted. Original sample used
// `await fetch(url, { signal: AbortSignal.timeout(5000) })` — the
// K17-compliant shape. K13 still tokenises the network read as
// externally-sourced content flowing into the tool response, producing
// an FP that is outside the K17 stress surface. Ship metadata-only.
const sourceCode = null;

export const k17AbortSignalTimeoutFixture: BenignFixture = {
  id: "edge-of-spec/k17-abort-signal-timeout",
  bucket: "edge-of-spec",
  why_benign:
    "K17 Missing Timeout. Uses AbortSignal.timeout(5000) — 5s hard deadline " +
    "is explicit; K17 must recognise the AbortSignal-timeout pattern.",
  context: {
    server: {
      id: "edge/k17-timeout",
      name: "bounded-fetch",
      description: "Fetch helper with explicit 5s timeout.",
      github_url: null,
    },
    tools: [
      {
        name: "upstream_call",
        description: "Fetch a URL with a 5-second hard timeout.",
        input_schema: {
          type: "object",
          properties: {
            service_name: {
              type: "string",
              enum: ["primary", "secondary"],
            },
          },
          required: ["service_name"],
          additionalProperties: false,
        },
        annotations: { readOnlyHint: true },
      },
    ],
    source_code: sourceCode,
    dependencies: [],
    connection_metadata: null,
  },
};
