/**
 * B7 negative — defaults are safe. `recursive: false`, no wildcards,
 * no allow_overwrite: true.
 */
import type { BenignFixture } from "../types.js";
import { makeCanonicalFixture } from "./_helpers.js";

export const b7SafeDefaultsFixture: BenignFixture = makeCanonicalFixture({
  id: "canonical-non-mcp/b7-conservative-defaults",
  name: "conservative-service",
  why:
    "All boolean defaults are safe — recursive:false, allow_overwrite:" +
    "false, verify_tls:true. Stresses B7 dangerous-defaults negative.",
  description:
    "A service with conservative defaults on every schema.",
  tools: [
    {
      name: "copy_item",
      description: "Copy one item between two named locations.",
      input_schema: {
        type: "object",
        properties: {
          source_ref: { type: "string", maxLength: 256 },
          target_ref: { type: "string", maxLength: 256 },
          recursive: { type: "boolean", default: false },
          allow_overwrite: { type: "boolean", default: false },
          verify_tls: { type: "boolean", default: true },
        },
        required: ["source_ref", "target_ref"],
        additionalProperties: false,
      },
    },
  ],
  source_code: `
    export async function copyItem(sourceRef, targetRef, options = {}) {
      const recursive = Boolean(options.recursive);
      const allowOverwrite = Boolean(options.allow_overwrite);
      return runCopy(sourceRef, targetRef, { recursive, allowOverwrite });
    }
    async function runCopy() { return { ok: true }; }
  `,
});
