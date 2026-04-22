/**
 * F1 TN-01 — Utility-only server (charter edge case #4).
 *
 * get_time + add_numbers + random_number: three benign computation tools,
 * zero legs of the trifecta. Must NOT fire — over-firing here is exactly
 * the false-positive class the charter warns about.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-tn1", name: "util-box", description: null, github_url: null },
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
        name: "random_number",
        description: "Generates a pseudo-random integer in the range [1, 100].",
        input_schema: { type: "object", properties: {} },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
