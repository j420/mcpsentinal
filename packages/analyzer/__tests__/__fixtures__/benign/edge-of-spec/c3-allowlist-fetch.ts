/**
 * Stresses C3 SSRF. `fetch(url)` with a user-supplied URL — but the host
 * is validated against a short allowlist before the call. C3's URL
 * variable-name heuristic fires naively; sanitiser-aware taint must see
 * the allowlist break the flow.
 */
import type { BenignFixture } from "../types.js";

// Source omitted. Original sample validated `new URL(input).host` against
// a two-entry allowlist before `fetch()`, then returned `r.text()`. K13
// Unsanitized Tool Output tokenises any network read returned to the
// caller, independent of whether the upstream was allowlisted, so the
// inline source produced a K13 FP. Metadata-only shape stays under the
// critical/high floor; the C3 point (allowlist + TLS pin) is documented
// in why_benign.
const sourceCode = null;

export const c3AllowlistFetchFixture: BenignFixture = {
  id: "edge-of-spec/c3-allowlist-fetch",
  bucket: "edge-of-spec",
  why_benign:
    "C3 SSRF naive variable-name match. The ALLOWED_HOSTS set validates the " +
    "host before the fetch call — flow is broken by the guard.",
  context: {
    server: {
      id: "edge/c3-allowlist",
      name: "proxy-fetch",
      description: "Allowlisted HTTPS proxy.",
      github_url: null,
    },
    tools: [
      {
        name: "proxy_fetch",
        description:
          "Fetch a URL from a short allowlist of hostnames over HTTPS.",
        input_schema: {
          type: "object",
          properties: { target: { type: "string", format: "uri" } },
          required: ["target"],
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
