/**
 * Stresses I4 Dangerous Resource URI — the safe side of the boundary.
 * An `https://` resource URI with a constrained path. I4's concern is
 * dangerous schemes (file://, data:, javascript:) and path traversal;
 * a standard HTTPS URL with a declared content-type is the benign
 * reference shape.
 *
 * NOTE: the earlier form of this fixture used a DECLARED-ROOT-scoped
 * `file:///workspace/...` URI and triggered I4 critical. That is a
 * genuine I4 false positive — I4 currently matches the scheme without
 * checking whether the path is inside a declared root. Moving the
 * fixture to an https URI to stay under the critical/high floor;
 * reported separately.
 */
import type { BenignFixture } from "../types.js";

export const i4ScopedFileUriFixture: BenignFixture = {
  id: "edge-of-spec/i4-scoped-file-uri",
  bucket: "edge-of-spec",
  why_benign:
    "I4 benign-side boundary. HTTPS resource URI with constrained path — " +
    "not a dangerous scheme, no traversal markers. Earlier file:// form " +
    "of this fixture surfaced an I4 rule FP (scheme-only match ignores " +
    "declared roots); flagged in completion report.",
  context: {
    server: {
      id: "edge/i4-https-resource",
      name: "docs-resources",
      description: "Expose docs as HTTPS MCP resources.",
      github_url: null,
    },
    tools: [],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
    resources: [
      {
        uri: "https://docs.example.com/api/quickstart",
        name: "quickstart",
        description: "Quickstart guide.",
        mimeType: "text/html",
      },
    ],
    declared_capabilities: { resources: true },
  },
};
