/**
 * Stresses P1 (base image security). `gcr.io/distroless/nodejs20-debian12`
 * is a minimal, well-maintained distroless image — the canonical
 * compliant base. P1 fires on `latest` tags, unpinned registries, or
 * shell-containing images; distroless is the reference-good shape.
 */
import type { BenignFixture } from "../types.js";

const sourceCode = `FROM gcr.io/distroless/nodejs20-debian12:nonroot

WORKDIR /app
COPY --from=build /app/dist /app/dist
COPY --from=build /app/node_modules /app/node_modules
USER nonroot
ENTRYPOINT ["/nodejs/bin/node", "dist/index.js"]
`;

export const p1DistrolessFixture: BenignFixture = {
  id: "edge-of-spec/p1-distroless",
  bucket: "edge-of-spec",
  why_benign:
    "P1 base image security. Uses gcr.io/distroless/nodejs20-debian12:" +
    "nonroot — minimal, trusted registry, non-root by default.",
  context: {
    server: {
      id: "edge/p1-distroless",
      name: "distroless-service",
      description: "Minimal distroless Node service.",
      github_url: null,
    },
    tools: [],
    source_code: sourceCode,
    dependencies: [],
    connection_metadata: null,
  },
};
