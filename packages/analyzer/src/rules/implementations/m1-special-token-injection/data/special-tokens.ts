/**
 * M1 — Special-token catalogue.
 *
 * Typed record of LLM chat-template control tokens the scanner looks for
 * in tool metadata. Each entry is a single record so the file is well
 * below the no-static-patterns string-array ceiling.
 *
 * Sources: OpenAI ChatML, Llama-2/Llama-3, Mistral, Claude Messages format,
 * GPT-4o, plus Anthropic red-team research 2024. The `kind` field feeds
 * the evidence-chain narrative and the multi-class confidence factor.
 */

export type TokenClass =
  | "chatml_role_delimiter"
  | "chatml_sentinel"
  | "llama_inst_block"
  | "llama_sys_block"
  | "llama3_header"
  | "conversation_role_marker";

export interface SpecialTokenSpec {
  /** Exact codepoint sequence to match via indexOf (case-insensitive). */
  readonly literal: string;
  readonly kind: TokenClass;
  /** Human-readable label for chain narrative. */
  readonly label: string;
  /**
   * When true, the token is only meaningful at a "boundary" position
   * (start of string, after newline, after whitespace). Used for
   * conversation role markers to suppress false positives on prose
   * like "the Human: field holds the user's name".
   */
  readonly boundary_only: boolean;
}

/**
 * Key = the token literal lowercased so the scanner can use a single case
 * fold. Value carries the original cased form + kind + label.
 */
export const SPECIAL_TOKENS: Readonly<Record<string, SpecialTokenSpec>> = {
  "<|im_start|>": {
    literal: "<|im_start|>",
    kind: "chatml_role_delimiter",
    label: "ChatML role delimiter (start)",
    boundary_only: false,
  },
  "<|im_end|>": {
    literal: "<|im_end|>",
    kind: "chatml_role_delimiter",
    label: "ChatML role delimiter (end)",
    boundary_only: false,
  },
  "<|system|>": {
    literal: "<|system|>",
    kind: "chatml_role_delimiter",
    label: "ChatML system role marker",
    boundary_only: false,
  },
  "<|assistant|>": {
    literal: "<|assistant|>",
    kind: "chatml_role_delimiter",
    label: "ChatML assistant role marker",
    boundary_only: false,
  },
  "<|user|>": {
    literal: "<|user|>",
    kind: "chatml_role_delimiter",
    label: "ChatML user role marker",
    boundary_only: false,
  },
  "<|endoftext|>": {
    literal: "<|endoftext|>",
    kind: "chatml_sentinel",
    label: "GPT end-of-text sentinel",
    boundary_only: false,
  },
  "<|begin_of_text|>": {
    literal: "<|begin_of_text|>",
    kind: "chatml_sentinel",
    label: "Llama begin-of-text sentinel",
    boundary_only: false,
  },
  "<|end_of_text|>": {
    literal: "<|end_of_text|>",
    kind: "chatml_sentinel",
    label: "Llama end-of-text sentinel",
    boundary_only: false,
  },
  "<|eot_id|>": {
    literal: "<|eot_id|>",
    kind: "llama3_header",
    label: "Llama-3 end-of-turn id",
    boundary_only: false,
  },
  "<|start_header_id|>": {
    literal: "<|start_header_id|>",
    kind: "llama3_header",
    label: "Llama-3 header start",
    boundary_only: false,
  },
  "<|end_header_id|>": {
    literal: "<|end_header_id|>",
    kind: "llama3_header",
    label: "Llama-3 header end",
    boundary_only: false,
  },
  "[inst]": {
    literal: "[INST]",
    kind: "llama_inst_block",
    label: "Llama/Mistral instruction block (open)",
    boundary_only: false,
  },
  "[/inst]": {
    literal: "[/INST]",
    kind: "llama_inst_block",
    label: "Llama/Mistral instruction block (close)",
    boundary_only: false,
  },
  "<<sys>>": {
    literal: "<<SYS>>",
    kind: "llama_sys_block",
    label: "Llama system block (open)",
    boundary_only: false,
  },
  "<</sys>>": {
    literal: "<</SYS>>",
    kind: "llama_sys_block",
    label: "Llama system block (close)",
    boundary_only: false,
  },
  // Conversation role markers — only flag at boundary positions to avoid
  // false-positive hits on prose like "the Human: field".
  "system:": {
    literal: "System:",
    kind: "conversation_role_marker",
    label: "conversation role marker (system)",
    boundary_only: true,
  },
  "assistant:": {
    literal: "Assistant:",
    kind: "conversation_role_marker",
    label: "conversation role marker (assistant)",
    boundary_only: true,
  },
  "human:": {
    literal: "Human:",
    kind: "conversation_role_marker",
    label: "conversation role marker (human)",
    boundary_only: true,
  },
};

/**
 * Confidence cap for M1. Applied in the chain builder.
 */
export const M1_CONFIDENCE_CAP = 0.88;

/**
 * Red-team fence tokens. If any of these appear in the same surface, the
 * confidence factor `red_team_fence` demotes confidence by 0.15 because
 * this class of tool legitimately carries control tokens as subject matter.
 */
export const RED_TEAM_FENCE_TOKENS: ReadonlyArray<string> = [
  "red-team",
  "red_team",
  "safety eval",
  "prompt-engineering",
];
