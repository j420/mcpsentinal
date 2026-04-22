/**
 * D1 / D6 negative — dependency pinned at a version above all known
 * CVE-affected ranges. Rule should NOT flag.
 */
import type { BenignFixture } from "../types.js";
import { makeCanonicalFixture, FRESH } from "./_helpers.js";

export const d1PatchedVersionFixture: BenignFixture = makeCanonicalFixture({
  id: "canonical-non-mcp/d1-patched-version-above-cve-bound",
  name: "patched-service",
  why:
    "Every dependency listed has has_known_cve:false and a version " +
    "above the historical CVE range. Stresses D1 CVE audit negative " +
    "and D6 weak-crypto-deps negative.",
  description:
    "A service that depends on patched versions of common libraries.",
  tools: [
    {
      name: "noop",
      description: "No-operation — exists so the tool count is non-zero.",
      input_schema: {
        type: "object",
        properties: {},
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
  ],
  source_code: `
    export async function noop() {
      return { ok: true };
    }
  `,
  extraDeps: [
    {
      name: "lodash",
      version: "4.17.21",
      has_known_cve: false,
      cve_ids: [],
      last_updated: FRESH,
    },
    {
      name: "jsonwebtoken",
      version: "9.0.2",
      has_known_cve: false,
      cve_ids: [],
      last_updated: FRESH,
    },
    {
      name: "bcrypt",
      version: "5.1.1",
      has_known_cve: false,
      cve_ids: [],
      last_updated: FRESH,
    },
  ],
});

