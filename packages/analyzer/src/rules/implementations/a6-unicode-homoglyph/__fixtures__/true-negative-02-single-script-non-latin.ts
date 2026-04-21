/**
 * A6 TN #2 — Legitimate non-Latin single-script identifier.
 *
 * A Russian-language MCP server documents a tool in Russian; the tool name
 * is entirely Cyrillic and the description is entirely Cyrillic prose. There
 * is NO Latin character to impersonate — therefore no homoglyph attack is
 * possible. The rule's script-mixing policy must correctly exclude this.
 */

import type { AnalysisContext } from "../../../../engine.js";

export const fixture: AnalysisContext = {
  server: {
    id: "tn-02",
    name: "русский-сервер",
    description: "MCP-сервер для русскоязычных пользователей",
    github_url: null,
  },
  tools: [
    {
      // Entirely Cyrillic — "прочитать_файл" = "read_file" in Russian
      name: "прочитать_файл",
      description: "Прочитать содержимое файла по указанному пути.",
      input_schema: null,
    },
  ],
  source_code: null,
  dependencies: [],
  connection_metadata: null,
};

export const expectation = {
  rule_id: "A6",
  min_findings: 0,
  max_findings: 0,
  rationale:
    "Single-script identifier (pure Cyrillic) cannot be a homoglyph attack — there is no Latin letter being impersonated.",
};
