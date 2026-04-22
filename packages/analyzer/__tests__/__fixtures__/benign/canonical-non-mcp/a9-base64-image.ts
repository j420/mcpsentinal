/**
 * A9 negative — a base64-encoded image blob in a schema default / example.
 * The rule should distinguish image bytes (high-entropy, no instruction
 * text when decoded) from instructions hidden in base64.
 */
import type { BenignFixture } from "../types.js";
import { makeCanonicalFixture } from "./_helpers.js";

/** 1x1 transparent PNG — legitimate binary data, not instructions. */
const PNG_1X1 =
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=";

export const a9Base64ImageFixture: BenignFixture = makeCanonicalFixture({
  id: "canonical-non-mcp/a9-base64-image-in-schema",
  name: "image-stamp",
  why:
    "A schema example containing a legitimate base64 PNG. Stresses A9 " +
    "encoded-instructions negative — decoded bytes are image data, not " +
    "natural-language instructions.",
  description:
    "Image stamper. Returns the supplied base64 image with a watermark " +
    "applied in the bottom-right corner.",
  tools: [
    {
      name: "stamp_image",
      description:
        "Take a PNG image (base64) and return the same image with a " +
        "watermark stamp applied.",
      input_schema: {
        type: "object",
        properties: {
          image_png_base64: { type: "string", maxLength: 2097152 },
          watermark_text: { type: "string", maxLength: 64 },
        },
        required: ["image_png_base64", "watermark_text"],
        additionalProperties: false,
        examples: [
          {
            image_png_base64: PNG_1X1,
            watermark_text: "© 2026",
          },
        ],
      },
    },
  ],
  source_code: `
    export async function stampImage(b64, text) {
      const bytes = Buffer.from(b64, "base64");
      if (bytes.length > 2_000_000) throw new Error("too large");
      const watermarked = await applyWatermark(bytes, String(text).slice(0, 64));
      return { png_base64: watermarked.toString("base64") };
    }
  `,
});
