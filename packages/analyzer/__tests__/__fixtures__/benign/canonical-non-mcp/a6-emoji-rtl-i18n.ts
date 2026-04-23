/**
 * A6/A7 negative — legitimate emoji and RTL language in descriptions.
 * The tool description contains Arabic + Hebrew + emoji; the rule must
 * distinguish i18n from homoglyph / zero-width injection.
 */
import type { BenignFixture } from "../types.js";
import { makeCanonicalFixture } from "./_helpers.js";

export const a6EmojiRtlFixture: BenignFixture = makeCanonicalFixture({
  id: "canonical-non-mcp/a6-emoji-rtl-i18n",
  name: "i18n-weather",
  why:
    "Legitimate i18n content — Arabic + Hebrew characters in a " +
    "bilingual description. Stresses A6 Unicode-homoglyph negative and " +
    "A7 zero-width-injection negative (RTL letters are script letters, " +
    "not control characters).",
  description:
    "Bilingual weather tool. Returns the current temperature and a " +
    "short forecast. Supports English, العربية (Arabic), and " +
    "עברית (Hebrew). 🌤️🌧️🌬️",
  tools: [
    {
      name: "current_temperature",
      description:
        "Return the current temperature for a city. City names may be " +
        "supplied in English, Arabic, or Hebrew.",
      input_schema: {
        type: "object",
        properties: {
          city: { type: "string", maxLength: 128 },
          units: { type: "string", enum: ["celsius", "fahrenheit"] },
        },
        required: ["city"],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
  ],
  source_code: `
    export async function currentTemperature(city, units) {
      const normalised = String(city).normalize("NFC").slice(0, 128);
      const reading = await weatherApi.lookup(normalised);
      return { city: normalised, units, degrees: reading.degrees };
    }
  `,
});
