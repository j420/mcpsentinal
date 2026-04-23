/**
 * Stresses P3 (non-root Dockerfile user). The Dockerfile ends with
 * `USER 1001` — explicit non-root numeric UID. P3 fires when a
 * Dockerfile lacks a USER directive or runs as root; explicit numeric
 * USER is the compliant shape.
 */
import type { BenignFixture } from "../types.js";

const sourceCode = `FROM node:20.11.1-bookworm-slim

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && \\
    groupadd --gid 1001 app && \\
    useradd --uid 1001 --gid 1001 --shell /usr/sbin/nologin --create-home app && \\
    chown -R app:app /app
COPY --chown=app:app . .

USER 1001
EXPOSE 8080
CMD ["node", "dist/index.js"]
`;

export const p3NonRootUserFixture: BenignFixture = {
  id: "edge-of-spec/p3-non-root-user",
  bucket: "edge-of-spec",
  why_benign:
    "P3 non-root user. Dockerfile sets explicit `USER 1001` — compliant " +
    "non-root shape.",
  context: {
    server: {
      id: "edge/p3-nonroot",
      name: "non-root-service",
      description: "Service that drops to UID 1001.",
      github_url: null,
    },
    tools: [],
    source_code: sourceCode,
    dependencies: [],
    connection_metadata: null,
  },
};
