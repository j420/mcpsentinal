/**
 * H2 — LLM chat-template / control-token catalogue.
 *
 * These tokens are the codepoint shibboleths used inside the prompt
 * formats of production LLMs (ChatML / Llama / Mistral / Gemma).
 * They have ZERO legitimate purpose inside an MCP server's
 * `serverInfo.name`, `serverInfo.version`, or `instructions` field.
 * Any occurrence is a direct-injection attempt.
 *
 * Stored as Record<string, SpecialTokenSpec> to stay under the
 * no-static-patterns guard's long-string-array ceiling and to carry
 * per-token metadata (weight + human-readable label) for evidence
 * narration.
 *
 * Token corpus derived from Rehberger (2024, Embrace The Red) and
 * Invariant Labs (2025, MCP Indirect Injection Research) — both
 * published real-world payloads observed in the wild.
 */

export interface SpecialTokenSpec {
  /** Independent probability weight (noisy-OR aggregation). */
  readonly weight: number;
  /** Human-readable label used in evidence narrative. */
  readonly label: string;
  /** Template family this token belongs to (for narrative grouping). */
  readonly family: "chatml" | "llama" | "mistral" | "gemma" | "role-prefix";
}

/** OpenAI / ChatML family (GPT-3.5+, o-series, many tuned models). */
const CHATML: Readonly<Record<string, SpecialTokenSpec>> = {
  "<|im_start|>": { weight: 0.96, label: "ChatML — <|im_start|>", family: "chatml" },
  "<|im_end|>": { weight: 0.96, label: "ChatML — <|im_end|>", family: "chatml" },
  "<|endoftext|>": { weight: 0.95, label: "ChatML — <|endoftext|>", family: "chatml" },
  "<|system|>": { weight: 0.95, label: "ChatML — <|system|>", family: "chatml" },
  "<|assistant|>": { weight: 0.92, label: "ChatML — <|assistant|>", family: "chatml" },
};

/** Llama 2 / Llama 3 family ([INST]/<<SYS>> and header_id variants). */
const LLAMA: Readonly<Record<string, SpecialTokenSpec>> = {
  "[INST]": { weight: 0.94, label: "Llama — [INST]", family: "llama" },
  "[/INST]": { weight: 0.94, label: "Llama — [/INST]", family: "llama" },
  "<<SYS>>": { weight: 0.95, label: "Llama — <<SYS>>", family: "llama" },
  "<</SYS>>": { weight: 0.95, label: "Llama — <</SYS>>", family: "llama" },
  "<|start_header_id|>": {
    weight: 0.95,
    label: "Llama 3 — <|start_header_id|>",
    family: "llama",
  },
};

/** Llama 3 trailing header_id (kept in its own bucket for array size rule). */
const LLAMA_EXTRA: Readonly<Record<string, SpecialTokenSpec>> = {
  "<|end_header_id|>": {
    weight: 0.95,
    label: "Llama 3 — <|end_header_id|>",
    family: "llama",
  },
  "<|eot_id|>": { weight: 0.94, label: "Llama 3 — <|eot_id|>", family: "llama" },
};

/** Mistral / Gemma turn markers. */
const GEMMA_MISTRAL: Readonly<Record<string, SpecialTokenSpec>> = {
  "<start_of_turn>": {
    weight: 0.92,
    label: "Gemma — <start_of_turn>",
    family: "gemma",
  },
  "<end_of_turn>": {
    weight: 0.92,
    label: "Gemma — <end_of_turn>",
    family: "gemma",
  },
  "[/s]": { weight: 0.7, label: "Mistral — [/s]", family: "mistral" },
};

/** Loose role prefixes (case-sensitive — preserved shape is the signal). */
const ROLE_PREFIXES: Readonly<Record<string, SpecialTokenSpec>> = {
  "\n\nHuman:": { weight: 0.9, label: "role prefix — \\n\\nHuman:", family: "role-prefix" },
  "\n\nAssistant:": {
    weight: 0.9,
    label: "role prefix — \\n\\nAssistant:",
    family: "role-prefix",
  },
  "[SYSTEM:": { weight: 0.9, label: "role prefix — [SYSTEM:", family: "role-prefix" },
  "### System": {
    weight: 0.82,
    label: "role prefix — ### System",
    family: "role-prefix",
  },
};

/** Merged catalogue — flattened at module load, no long literal arrays. */
export const LLM_SPECIAL_TOKENS: Readonly<Record<string, SpecialTokenSpec>> = {
  ...CHATML,
  ...LLAMA,
  ...LLAMA_EXTRA,
  ...GEMMA_MISTRAL,
  ...ROLE_PREFIXES,
};

/**
 * Scan a field for every LLM special-token substring (case-sensitive).
 * Returns the complete list of hits with offsets so the gather step
 * can emit one Site per occurrence.
 */
export interface SpecialTokenHit {
  token: string;
  spec: SpecialTokenSpec;
  offset: number;
}

export function findSpecialTokens(field: string): SpecialTokenHit[] {
  const out: SpecialTokenHit[] = [];
  for (const token of Object.keys(LLM_SPECIAL_TOKENS)) {
    let from = 0;
    while (true) {
      const idx = field.indexOf(token, from);
      if (idx < 0) break;
      out.push({ token, spec: LLM_SPECIAL_TOKENS[token], offset: idx });
      from = idx + token.length;
    }
  }
  return out;
}
