import type { AnalysisContext } from "../../../../engine.js";

/**
 * Cyrillic 'е' (U+0435) replaces Latin 'e' (U+0065) in the first char.
 * After Unicode confusable normalisation the name becomes "event-stream",
 * which IS in the blocklist.
 */
export function buildContext(): AnalysisContext {
  const cyrillicE = String.fromCodePoint(0x0435);
  const homoglyphName = `${cyrillicE}vent-stream`;
  return {
    server: { id: "srv-1", name: "t", description: null, github_url: null },
    tools: [],
    source_code: null,
    dependencies: [
      { name: homoglyphName, version: "3.3.6", has_known_cve: false, cve_ids: [], last_updated: null },
    ],
    connection_metadata: null,
  };
}
