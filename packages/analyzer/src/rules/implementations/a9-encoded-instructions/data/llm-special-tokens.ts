/**
 * LLM chat-template / role markers used by A9.
 *
 * When a decoded payload contains any of these, the confidence that the
 * encoded block is a genuine prompt-injection attempt rises sharply —
 * these tokens only make sense inside model-level control-plane text,
 * never inside a legitimate tool description.
 *
 * Stored as `Record<string, true>` to avoid the "long string-array"
 * lint heuristic and to match the lookup pattern used elsewhere (K7, K1).
 */

export const LLM_SPECIAL_TOKENS: Record<string, true> = {
  // OpenAI / ChatML style
  "<|im_start|>": true,
  "<|im_end|>": true,
  "<|endoftext|>": true,
  // Anthropic historical HUMAN/ASSISTANT markers
  "\n\nHuman:": true,
  "\n\nAssistant:": true,
  "Human:": true,
  "Assistant:": true,
  // Llama 2 / 3 chat templates
  "[INST]": true,
  "[/INST]": true,
  "<<SYS>>": true,
  "<</SYS>>": true,
  // Mistral / Gemma style
  "<start_of_turn>": true,
  "<end_of_turn>": true,
  // Generic role prefixes (case-sensitive — real tokens preserve case)
  "system:": true,
  "user:": true,
  "assistant:": true,
};

/**
 * Scan a decoded payload for any LLM special-token or role marker.
 * Returns the first match (or null) — one is enough to raise confidence.
 */
export function findLLMSpecialToken(decoded: string): string | null {
  for (const tok of Object.keys(LLM_SPECIAL_TOKENS)) {
    if (decoded.includes(tok)) return tok;
  }
  return null;
}
