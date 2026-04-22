/**
 * Benign fixture catalogue — 145 fixtures across four provenance buckets.
 * Combined with the 55 inline fixtures in `benign-corpus.test.ts`, gives
 * 200 total benign regression cases.
 */
import type { BenignFixture } from "./types.js";
import { anthropicOfficialFixtures } from "./anthropic-official/index.js";
import { smitheryTopFixtures } from "./smithery-top/index.js";
import { canonicalNonMcpFixtures } from "./canonical-non-mcp/index.js";
import { edgeOfSpecFixtures } from "./edge-of-spec/index.js";

export type { BenignFixture, BenignBucket, AllowedFinding } from "./types.js";

export const benignCatalogue: readonly BenignFixture[] = [
  ...anthropicOfficialFixtures,
  ...smitheryTopFixtures,
  ...canonicalNonMcpFixtures,
  ...edgeOfSpecFixtures,
];

export {
  anthropicOfficialFixtures,
  smitheryTopFixtures,
  canonicalNonMcpFixtures,
  edgeOfSpecFixtures,
};
