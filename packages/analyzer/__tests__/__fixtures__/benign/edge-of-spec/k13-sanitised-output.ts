/**
 * Stresses K13 Unsanitized Tool Output. The response string is passed
 * through a sanitisation function (`sanitiseForLLM`) before being
 * emitted. K13 fires when raw upstream data flows directly to the
 * tool response; a sanitisation step breaks that flow.
 */
import type { BenignFixture } from "../types.js";

const sourceCode = `/** Strip control characters, zero-width chars, and escape ASCII 127-159. */
function sanitiseForLLM(input: string): string {
  let out = "";
  for (const ch of input) {
    const code = ch.codePointAt(0) ?? 0;
    if (code < 0x20 || (code >= 0x7f && code <= 0x9f)) continue;
    if (code === 0x200b || code === 0x200c || code === 0x200d) continue;
    out += ch;
  }
  return out;
}

export async function summarise(userBody: string): Promise<{ summary: string }> {
  const cleaned = sanitiseForLLM(userBody);
  return { summary: cleaned.slice(0, 200) };
}
`;

export const k13SanitisedOutputFixture: BenignFixture = {
  id: "edge-of-spec/k13-sanitised-output",
  bucket: "edge-of-spec",
  why_benign:
    "K13 Unsanitized Tool Output. Output passes through an explicit " +
    "sanitise step (control chars + zero-width stripped) before emission.",
  context: {
    server: {
      id: "edge/k13-sanitise",
      name: "summary-helper",
      description: "Return a sanitised summary.",
      github_url: null,
    },
    tools: [
      {
        name: "summarise",
        description: "Return a sanitised, length-capped summary of the input.",
        input_schema: {
          type: "object",
          properties: { body: { type: "string", maxLength: 16384 } },
          required: ["body"],
          additionalProperties: false,
        },
        annotations: { readOnlyHint: true },
      },
    ],
    source_code: sourceCode,
    dependencies: [],
    connection_metadata: null,
  },
};
