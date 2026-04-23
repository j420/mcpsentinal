/**
 * Stresses A5 Description Length Anomaly. A ~1600-character description
 * crosses the length heuristic, but every paragraph is genuine API
 * documentation: parameter reference, return schema, worked examples.
 * No injection markers, no role framing, no encoding.
 * A5 should not fire critical/high; at most low/informational.
 */
import type { BenignFixture } from "../types.js";

const longDescription = [
  "Format a number as a currency string in a given locale. This helper ",
  "accepts a numeric amount and an IANA currency code and returns a ",
  "locale-formatted string ready for display in the product UI. The ",
  "formatter is a thin wrapper around the platform's Intl.NumberFormat ",
  "with a consistent default for fraction digits. ",
  "\n\nArguments: `amount` is the numeric amount as a finite number, ",
  "`currency` is a three-letter ISO 4217 code, `locale` is an optional ",
  "BCP 47 locale tag that defaults to the server's configured locale. ",
  "\n\nReturn value: a plain string containing the formatted currency. ",
  "Behaviour matches what you would see from Intl.NumberFormat with ",
  "currency style. ",
  "\n\nWorked example: formatting 1234.5 with currency USD and locale ",
  "en-US yields '$1,234.50'. Formatting 1234.5 with currency EUR and ",
  "locale de-DE yields '1.234,50 EUR'. ",
  "\n\nEdge cases: non-finite numbers (NaN, Infinity) raise a typed ",
  "error rather than produce an undefined string. Unknown currency ",
  "codes raise a typed error as well. Empty-string locale falls back ",
  "to the configured default. The formatter is pure — no external ",
  "calls, no state, fully deterministic given the inputs. ",
  "\n\nPerformance: roughly a few microseconds per call on a modern ",
  "runtime. The underlying Intl machinery caches its formatters ",
  "internally, so repeated calls with the same locale-currency pair ",
  "are effectively free. ",
  "\n\nThis helper is a building block for the higher-level report ",
  "renderers shipped elsewhere in the server. Those renderers layer on ",
  "grouping rules, accessibility annotations, and print-mode variants.",
].join("");

export const a5LongTutorialFixture: BenignFixture = {
  id: "edge-of-spec/a5-long-tutorial",
  bucket: "edge-of-spec",
  why_benign:
    "A5 Description Length Anomaly. ~1.6k chars of legitimate tutorial " +
    "content, no injection markers, neutral vocabulary. A5 may emit " +
    "informational/low; critical/high would be a rule FP.",
  context: {
    server: {
      id: "edge/a5-tutorial",
      name: "number-format",
      description: "Currency formatting helper.",
      github_url: null,
    },
    tools: [
      {
        name: "format_currency",
        description: longDescription,
        input_schema: {
          type: "object",
          properties: {
            amount: { type: "number" },
            currency: { type: "string", pattern: "^[A-Z]{3}$" },
            locale: { type: "string", maxLength: 35 },
          },
          required: ["amount", "currency"],
          additionalProperties: false,
        },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  },
  allowed_findings: [
    {
      rule_id: "A5",
      severity: "low",
      reason:
        "A5 may legitimately flag description length; semantics are benign " +
        "so informational/low is acceptable.",
    },
  ],
};
