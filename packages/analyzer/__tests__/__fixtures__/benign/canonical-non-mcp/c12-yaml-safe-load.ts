/**
 * C12 negative — yaml.safeLoad / yaml.load with safe schema. Does NOT
 * invoke arbitrary Python/JS deserialisation. Source code documents
 * the pattern without chaining readFile→safeLoad, which aggressive
 * static taint classifies as filesystem access.
 */
import type { BenignFixture } from "../types.js";
import { makeCanonicalFixture } from "./_helpers.js";

export const c12YamlSafeLoadFixture: BenignFixture = makeCanonicalFixture({
  id: "canonical-non-mcp/c12-yaml-safe-load",
  name: "config-parser",
  why:
    "yaml.safeLoad only accepts the core YAML schema — no tags, no " +
    "arbitrary constructor calls. Stresses C12 unsafe-deserialisation " +
    "negative.",
  description:
    "Parses a YAML text blob using the safe loader. Tags and custom " +
    "types are rejected.",
  tools: [
    {
      name: "parse_yaml_blob",
      description:
        "Parse a YAML text blob (already loaded into memory) with the " +
        "safe loader and return the resulting plain object graph.",
      input_schema: {
        type: "object",
        properties: {
          yaml_text: { type: "string", maxLength: 65536 },
        },
        required: ["yaml_text"],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
  ],
  source_code: `
    import { safeLoad } from "js-yaml";

    export function parseYamlBlob(yamlText) {
      // safeLoad with schema:'core' — rejects !!js/function, tagged
      // types, and every constructor-call form. Plain primitive /
      // object graph only. No deserialisation vulnerability.
      return safeLoad(String(yamlText), { schema: "core" });
    }
  `,
});
