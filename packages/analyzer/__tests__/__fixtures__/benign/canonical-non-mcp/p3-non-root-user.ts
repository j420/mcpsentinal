/**
 * P3 negative — Dockerfile with USER node after COPY.
 */
import type { BenignFixture } from "../types.js";
import { makeCanonicalFixture } from "./_helpers.js";

export const p3NonRootUserFixture: BenignFixture = makeCanonicalFixture({
  id: "canonical-non-mcp/p3-non-root-runtime-user",
  name: "non-root-service",
  why:
    "Container runtime drops to USER node after COPY. Stresses P3 " +
    "non-root-runtime negative.",
  description:
    "Service that runs under the unprivileged 'node' user inside " +
    "its container.",
  tools: [
    {
      name: "uptime",
      description: "Return the process uptime in seconds.",
      input_schema: {
        type: "object",
        properties: {},
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
  ],
  source_code: `
    // Dockerfile (illustrative, showing the USER switch):
    // FROM node:20-bookworm-slim AS build
    // WORKDIR /app
    // COPY . .
    // RUN corepack enable && pnpm install --frozen-lockfile && pnpm build
    //
    // FROM node:20-bookworm-slim
    // WORKDIR /app
    // COPY --from=build /app/dist ./dist
    // COPY --from=build /app/node_modules ./node_modules
    // USER node
    // CMD ["node", "dist/index.js"]
    export async function uptime() {
      return { seconds: process.uptime() };
    }
  `,
});
