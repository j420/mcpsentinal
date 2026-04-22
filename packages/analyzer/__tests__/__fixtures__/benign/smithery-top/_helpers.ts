/**
 * Shared dependency shapes for smithery-top fixtures. Central so we can
 * bump the recency dates in one place when the suite is re-run far from
 * the original authorship date.
 */
import type { BenignFixture } from "../types.js";

export const FRESH = new Date("2026-03-01");
export const FRESH_B = new Date("2026-02-10");
export const FRESH_C = new Date("2026-02-25");

export const MCP_SDK_DEP = {
  name: "@modelcontextprotocol/sdk" as const,
  version: "1.5.0",
  has_known_cve: false,
  cve_ids: [] as string[],
  last_updated: FRESH,
};

export const ZOD_DEP = {
  name: "zod" as const,
  version: "3.23.8",
  has_known_cve: false,
  cve_ids: [] as string[],
  last_updated: FRESH_C,
};

type FixtureBuilder = (input: {
  id: string;
  name: string;
  why: string;
  description: string;
  github_url: string;
  tools: BenignFixture["context"]["tools"];
  extraDeps?: BenignFixture["context"]["dependencies"];
}) => BenignFixture;

/** Construct a smithery-top fixture with common boilerplate. */
export const makeSmitheryFixture: FixtureBuilder = ({
  id,
  name,
  why,
  description,
  github_url,
  tools,
  extraDeps = [],
}) => ({
  id,
  bucket: "smithery-top",
  why_benign: why,
  context: {
    server: { id: name, name, description, github_url },
    tools,
    source_code: null,
    dependencies: [MCP_SDK_DEP, ZOD_DEP, ...extraDeps],
    connection_metadata: null,
  },
});
