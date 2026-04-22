/**
 * P1 negative — Dockerfile FROM node:20-bookworm-slim (pinned distro).
 */
import type { BenignFixture } from "../types.js";
import { makeCanonicalFixture } from "./_helpers.js";

export const p1PinnedDistroFixture: BenignFixture = makeCanonicalFixture({
  id: "canonical-non-mcp/p1-pinned-distro-base-image",
  name: "pinned-image",
  why:
    "Dockerfile pins the base image to node:20-bookworm-slim — distro " +
    "tag included, not :latest. Stresses P1 untrusted-base-image " +
    "negative.",
  description:
    "A small service shipped as a pinned Docker image.",
  tools: [
    {
      name: "healthz",
      description: "Return the service health status.",
      input_schema: {
        type: "object",
        properties: {},
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
  ],
  source_code: `
    // Dockerfile (illustrative):
    // FROM node:20-bookworm-slim
    // WORKDIR /app
    // COPY package.json pnpm-lock.yaml ./
    // RUN corepack enable && pnpm install --frozen-lockfile
    // COPY . .
    // USER node
    // CMD ["node", "dist/index.js"]
    export async function healthz() { return { ok: true }; }
  `,
});
