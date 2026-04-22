/**
 * I2 stub fixture — empty tool set. The stub always returns [] regardless.
 * Kept for directory-layout consistency with other v2 rules.
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-i2-stub", name: "empty", description: null, github_url: null },
    tools: [],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
