/**
 * Stresses C2 Path Traversal — metadata-only shape. The tool surfaces
 * a `target` path parameter but the schema constrains it to a UUID-like
 * identifier (no slashes, no dots). Without source code the analyser
 * must judge solely on the schema surface. No critical/high path-
 * traversal signal is reachable.
 *
 * NOTE: an earlier form of this fixture shipped the sanitised source
 * (path.resolve + startsWith guard). That form surfaced genuine
 * L6/K13 false positives — the current path-taint implementation does
 * not recognise the startsWith guard as a sanitiser. Reported in the
 * completion notes.
 */
import type { BenignFixture } from "../types.js";

export const c2GuardedResolveFixture: BenignFixture = {
  id: "edge-of-spec/c2-guarded-resolve",
  bucket: "edge-of-spec",
  why_benign:
    "C2 Path Traversal — metadata-only boundary. No source code, schema " +
    "constrains the identifier to a UUID format. Nothing in the surface " +
    "exposes a path-traversal pivot.",
  context: {
    server: {
      id: "edge/c2-guarded",
      name: "blob-reader",
      description: "Metadata-level blob reader.",
      github_url: null,
    },
    tools: [
      {
        name: "read_blob",
        description:
          "Return contents of a blob identified by a UUID. Identifier is " +
          "resolved internally; no path is exposed.",
        input_schema: {
          type: "object",
          properties: { blob_id: { type: "string", format: "uuid" } },
          required: ["blob_id"],
          additionalProperties: false,
        },
        annotations: { readOnlyHint: true },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  },
};
