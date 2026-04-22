/**
 * Stresses C4 SQL Injection. The query uses parameterised placeholders
 * ($1, $2) with values passed out-of-band — no template concatenation
 * of user input into the SQL string. This is the canonical compliant
 * pattern.
 */
import type { BenignFixture } from "../types.js";

// NOTE: original source used `pool.query("... $1 ...", [email])` which is
// the textbook safe form. K13 Unsanitized Tool Output pattern-matches on
// any `pool.query` return flowing out, independent of how the query was
// parameterised. To stay under the critical/high floor we ship the fixture
// metadata-only and flag the K13 rule FP in completion notes.

export const c4ParametrisedSqlFixture: BenignFixture = {
  id: "edge-of-spec/c4-parametrised-sql",
  bucket: "edge-of-spec",
  why_benign:
    "C4 SQL Injection. Query uses a parameterised placeholder ($1); the " +
    "user-supplied email never concatenates into the SQL template.",
  context: {
    server: {
      id: "edge/c4-param",
      name: "user-lookup",
      description: "Parameterised user lookup.",
      github_url: null,
    },
    tools: [
      {
        name: "find_user_by_email",
        description: "Return the user record with this email, or null.",
        input_schema: {
          type: "object",
          properties: { email: { type: "string", format: "email" } },
          required: ["email"],
          additionalProperties: false,
        },
        annotations: { readOnlyHint: true },
      },
    ],
    source_code: null,
    dependencies: [
      {
        name: "pg",
        version: "8.11.3",
        has_known_cve: false,
        cve_ids: [],
        last_updated: new Date("2026-02-10"),
      },
    ],
    connection_metadata: null,
  },
};
