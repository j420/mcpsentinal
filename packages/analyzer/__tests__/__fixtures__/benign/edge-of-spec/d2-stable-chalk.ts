/**
 * Stresses D2 Abandoned Dependencies (>12 months). `chalk` is a mature,
 * widely-used library that is stable by design — it doesn't need weekly
 * releases. A dependency just past the D2 threshold is not automatically
 * abandoned; D2 is heuristic and this is the false-positive boundary.
 */
import type { BenignFixture } from "../types.js";

export const d2StableChalkFixture: BenignFixture = {
  id: "edge-of-spec/d2-stable-chalk",
  bucket: "edge-of-spec",
  why_benign:
    "D2 >12-month threshold. `chalk` is mature/stable, last updated 18mo " +
    "ago — benign. D2 severity is medium at worst.",
  context: {
    server: {
      id: "edge/d2-chalk",
      name: "color-greeting",
      description: "Terminal colour helper.",
      github_url: null,
    },
    tools: [
      {
        name: "colour_text",
        description: "Wrap text in ANSI colour codes.",
        input_schema: {
          type: "object",
          properties: {
            text: { type: "string", maxLength: 1024 },
            colour: { type: "string", enum: ["red", "green", "blue", "yellow"] },
          },
          required: ["text", "colour"],
          additionalProperties: false,
        },
        annotations: { readOnlyHint: true },
      },
    ],
    source_code: null,
    dependencies: [
      {
        name: "chalk",
        version: "5.3.0",
        has_known_cve: false,
        cve_ids: [],
        last_updated: new Date("2024-10-10"),
      },
    ],
    connection_metadata: null,
  },
  allowed_findings: [
    {
      rule_id: "D2",
      severity: "medium",
      reason: "D2 threshold may trigger on mature/stable libraries; benign.",
    },
  ],
};
