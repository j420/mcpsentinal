/**
 * F2 stub fixture — empty tool set. The stub always returns [] regardless.
 * We still ship a fixture to keep the wave-2 directory layout consistent.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-f2-stub", name: "empty", description: null, github_url: null },
    tools: [],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
