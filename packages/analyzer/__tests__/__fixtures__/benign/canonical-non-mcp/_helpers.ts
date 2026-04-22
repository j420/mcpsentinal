/**
 * Shared dependency shapes for canonical-non-mcp fixtures.
 */
import type { BenignFixture } from "../types.js";

export const FRESH = new Date("2026-03-01");

export const MCP_SDK_DEP = {
  name: "@modelcontextprotocol/sdk" as const,
  version: "1.5.0",
  has_known_cve: false,
  cve_ids: [] as string[],
  last_updated: FRESH,
};

type FixtureBuilder = (input: {
  id: string;
  name: string;
  why: string;
  description: string;
  tools: BenignFixture["context"]["tools"];
  source_code: string;
  extraDeps?: BenignFixture["context"]["dependencies"];
}) => BenignFixture;

/** Build a canonical-non-mcp fixture with common boilerplate. */
export const makeCanonicalFixture: FixtureBuilder = ({
  id,
  name,
  why,
  description,
  tools,
  source_code,
  extraDeps = [],
}) => ({
  id,
  bucket: "canonical-non-mcp",
  why_benign: why,
  context: {
    server: {
      id: name,
      name,
      description,
      github_url: `https://github.com/sample/${name}`,
    },
    tools,
    source_code,
    dependencies: [MCP_SDK_DEP, ...extraDeps],
    connection_metadata: null,
  },
});
