/**
 * G1 TN-02 — Utility-only server, no ingestion surface at all.
 *
 * Three benign arithmetic / time tools. Zero ingestion capability on
 * any tool, so there is no gateway candidate. Even though one tool
 * could arguably classify as `sends-network` if the description
 * mentioned a URL, none of them does here. G1 must NOT fire — this
 * protects against the false-positive class of utility-tool
 * misclassification.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: {
      id: "srv-g1-tn2",
      name: "utility-box",
      description: null,
      github_url: null,
    },
    tools: [
      {
        name: "get_time",
        description: "Returns the current UTC timestamp in ISO-8601 format.",
        input_schema: { type: "object", properties: {} },
      },
      {
        name: "add_numbers",
        description: "Computes the sum of two numbers and returns the result.",
        input_schema: {
          type: "object",
          properties: {
            a: { type: "number" },
            b: { type: "number" },
          },
        },
      },
      {
        name: "random_integer",
        description: "Generates a pseudo-random integer in a bounded range.",
        input_schema: {
          type: "object",
          properties: {
            min: { type: "number" },
            max: { type: "number" },
          },
        },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
