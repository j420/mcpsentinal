/**
 * I4 negative — resource URI using a non-file custom scheme tied to a
 * narrow project scope. file:// schemes are inherently flagged by I4
 * (the rule is designed that way), so a benign fixture must use a
 * non-file scheme to exercise the negative path.
 */
import type { BenignFixture } from "../types.js";

export const i4ScopedResourceFixture: BenignFixture = {
  id: "canonical-non-mcp/i4-scoped-custom-scheme-resource",
  bucket: "canonical-non-mcp",
  why_benign:
    "Resource URIs use a custom in-process scheme (report://), not " +
    "file://, and therefore do not trigger I4's file-scheme rule. " +
    "Stresses I4 dangerous-resource-URI negative via the custom-scheme " +
    "path.",
  context: {
    server: {
      id: "report-library",
      name: "report-library",
      description:
        "Serves indexed reports as MCP resources via an in-process " +
        "report:// scheme. Resources are narrowly scoped to the " +
        "report index.",
      github_url: "https://github.com/sample/report-library",
    },
    tools: [],
    resources: [
      {
        uri: "report://monthly/2026-04",
        name: "April 2026 monthly",
        description: "April 2026 monthly report.",
        mimeType: "text/markdown",
      },
      {
        uri: "report://quarterly/2026-Q1",
        name: "2026 Q1 quarterly",
        description: "Q1 2026 quarterly report.",
        mimeType: "text/markdown",
      },
    ],
    source_code: null,
    dependencies: [
      {
        name: "@modelcontextprotocol/sdk",
        version: "1.5.0",
        has_known_cve: false,
        cve_ids: [],
        last_updated: new Date("2026-03-01"),
      },
    ],
    connection_metadata: null,
  },
};
