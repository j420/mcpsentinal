/**
 * Stresses G2 Trust Assertion Injection. The description contains NO
 * authority claims or certifications — it is a neutral factual
 * statement about what the tool does. The absence of "approved by X"
 * markers means G2 should stay silent. If G2 fires here the rule is
 * over-matching on any capitalised org name.
 */
import type { BenignFixture } from "../types.js";

export const g2FactualDocFixture: BenignFixture = {
  id: "edge-of-spec/g2-factual-doc",
  bucket: "edge-of-spec",
  why_benign:
    "G2 Trust Assertion Injection. Description is a neutral factual " +
    "statement — no 'approved by', no 'certified', no authority claim.",
  context: {
    server: {
      id: "edge/g2-factual",
      name: "factual-weather",
      description: "Return current weather for a city.",
      github_url: null,
    },
    tools: [
      {
        name: "current_weather",
        description:
          "Return the current temperature and conditions for a city. The " +
          "data source is the public OpenWeatherMap API. No authentication " +
          "is required from the caller.",
        input_schema: {
          type: "object",
          properties: {
            city: { type: "string", maxLength: 64 },
            country_code: {
              type: "string",
              pattern: "^[A-Z]{2}$",
            },
          },
          required: ["city", "country_code"],
          additionalProperties: false,
        },
        annotations: { readOnlyHint: true, destructiveHint: false },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  },
};
