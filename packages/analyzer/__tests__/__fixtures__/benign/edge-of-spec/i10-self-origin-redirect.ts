/**
 * Stresses I10 Elicitation URL Redirect. The tool description mentions
 * returning a URL, but the URL is always same-origin (the server's own
 * docs page) — not a redirect to an attacker-controlled site. I10
 * fires on off-origin redirects with auth implications; same-origin
 * help links are benign.
 */
import type { BenignFixture } from "../types.js";

export const i10SelfOriginRedirectFixture: BenignFixture = {
  id: "edge-of-spec/i10-self-origin-redirect",
  bucket: "edge-of-spec",
  why_benign:
    "I10 Elicitation URL Redirect. Returned URL is always same-origin " +
    "(server's own docs endpoint) — no off-origin redirect pivot.",
  context: {
    server: {
      id: "edge/i10-self-docs",
      name: "help-link",
      description: "Returns a same-origin help URL.",
      github_url: null,
    },
    tools: [
      {
        name: "open_help",
        description:
          "Return a link to this server's built-in docs page for the given " +
          "topic. The returned URL always resolves to the server's own " +
          "host and port.",
        input_schema: {
          type: "object",
          properties: {
            topic: { type: "string", enum: ["quickstart", "faq", "changelog"] },
          },
          required: ["topic"],
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
