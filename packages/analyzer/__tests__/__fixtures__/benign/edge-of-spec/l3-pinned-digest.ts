/**
 * Stresses L3 (Docker base-image pinning). This Dockerfile pins the
 * base image BOTH by tag AND by SHA256 digest — fully reproducible,
 * tamper-evident. L3 fires when a base image is floating or pinned
 * only by tag; a digest-pinned FROM is the compliant shape.
 */
import type { BenignFixture } from "../types.js";

const sourceCode = `FROM node:20.11.1-bookworm-slim@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY . .
USER 1001
CMD ["node", "dist/index.js"]
`;

export const l3PinnedDigestFixture: BenignFixture = {
  id: "edge-of-spec/l3-pinned-digest",
  bucket: "edge-of-spec",
  why_benign:
    "L3 base image is pinned by digest (@sha256:...) — reproducible, " +
    "tamper-evident. L3 should not fire on digest-pinned FROM.",
  context: {
    server: {
      id: "edge/l3-digest",
      name: "digest-pinned-service",
      description: "Service with a digest-pinned Dockerfile.",
      github_url: null,
    },
    tools: [],
    source_code: sourceCode,
    dependencies: [],
    connection_metadata: null,
  },
};
