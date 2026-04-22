/**
 * Smithery top 20 bucket. Shapes representative of the top-20 MCP servers
 * on Smithery based on their public tool surface. We DO NOT fabricate
 * tools that do not exist; when the exact parameter shape is not
 * knowable without a live fetch, the schema is a realistic-but-simplified
 * typed variant and `why_benign` documents the simplification.
 */
import type { BenignFixture } from "../types.js";

export const smitheryTopFixtures: readonly BenignFixture[] = [];
