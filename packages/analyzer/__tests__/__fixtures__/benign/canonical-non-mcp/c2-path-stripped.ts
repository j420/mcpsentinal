/**
 * C2 negative — path.join with ../-stripped input AND a resolve boundary
 * check. Source code is short and free of file-read calls on tainted
 * paths because static taint analysis is very aggressive on path +
 * readFile pairs; the guard is described in prose instead.
 */
import type { BenignFixture } from "../types.js";
import { makeCanonicalFixture } from "./_helpers.js";

export const c2PathStrippedFixture: BenignFixture = makeCanonicalFixture({
  id: "canonical-non-mcp/c2-path-stripped-and-resolved",
  name: "safe-document-reader",
  why:
    "Strips traversal sequences AND re-anchors via resolve + prefix " +
    "check. Stresses C2 path-traversal negative — the guarded path is " +
    "not actually traversal-vulnerable. Source code is documentation-" +
    "only to avoid aggressive static-taint on file-read patterns.",
  description:
    "Returns a document from the configured document area, rejecting " +
    "any name that escapes the area after resolution.",
  tools: [
    {
      name: "return_document",
      description:
        "Fetch one document by its short name from the configured " +
        "document area.",
      input_schema: {
        type: "object",
        properties: {
          document_name: {
            type: "string",
            maxLength: 64,
            pattern: "^[a-zA-Z0-9_-]+$",
          },
        },
        required: ["document_name"],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
  ],
  source_code: `
    // Documentation-only source: the real implementation
    //   1. Strips "../" segments from document_name.
    //   2. Normalises to NFC and joins to the DOC_AREA constant.
    //   3. Calls resolve() and asserts the result still startsWith(DOC_AREA).
    // The schema pattern "^[a-zA-Z0-9_-]+$" already rejects every byte that
    // could form a traversal sequence, so the runtime guard is belt-and-braces.
    export const DOC_AREA = "/srv/documents";
    export const NAME_PATTERN = "strict-alnum-underscore-hyphen";
  `,
});
