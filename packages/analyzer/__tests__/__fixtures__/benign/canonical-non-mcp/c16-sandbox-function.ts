/**
 * C16 negative — `new Function(...)` over STATIC string literals, never
 * user input. The dynamic-eval rule should distinguish compile-once
 * patterns from user-controlled evaluation.
 */
import type { BenignFixture } from "../types.js";
import { makeCanonicalFixture } from "./_helpers.js";

export const c16SandboxFunctionFixture: BenignFixture = makeCanonicalFixture({
  id: "canonical-non-mcp/c16-sandbox-function-literal-body",
  name: "math-kernel",
  why:
    "new Function is compiled once from a static literal body; user " +
    "input only fills the parameter placeholder. Stresses C16 dynamic-" +
    "code-evaluation negative.",
  description:
    "Numeric kernel. Applies a pre-compiled increment function to a " +
    "user-supplied integer and returns the result.",
  tools: [
    {
      name: "increment_by_one",
      description:
        "Return the supplied integer plus one. The increment is " +
        "computed via a pre-compiled arithmetic kernel.",
      input_schema: {
        type: "object",
        properties: {
          n: { type: "integer", minimum: -1000000, maximum: 1000000 },
        },
        required: ["n"],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
  ],
  source_code: `
    // Compiled once from a literal string; n is a parameter, not a
    // program. No user-controlled program text ever reaches Function.
    const increment = new Function("x", "return x + 1");

    export async function incrementByOne(n) {
      if (!Number.isInteger(n)) throw new Error("n must be an integer");
      const result = increment(n);
      return { result };
    }
  `,
});
