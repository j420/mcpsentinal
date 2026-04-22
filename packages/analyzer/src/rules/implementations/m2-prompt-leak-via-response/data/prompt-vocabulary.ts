/**
 * M2 prompt-leak vocabulary. Typed records replacing 3 regex groups.
 */
export const SYSTEM_PROMPT_IDENTIFIERS: readonly string[] = [
  "system_prompt",
  "systemPrompt",
  "system_message",
  "systemMessage",
  "initial_instructions",
];

export const SYSTEM_PROMPT_IDENTIFIERS_EXTRA: readonly string[] = [
  "initialInstructions",
  "system_instructions",
  "systemInstructions",
  "base_prompt",
  "basePrompt",
];

export const RESPONSE_SINK_METHODS: readonly string[] = [
  "send",
  "json",
  "write",
  "end",
  "respond",
];

export const RESPONSE_SINK_METHODS_EXTRA: readonly string[] = [
  "reply",
];

export const REDACTION_TOKENS: readonly string[] = [
  "redact",
  "strip",
  "mask",
  "removePrompt",
  "sanitize",
];

export const REDACTION_TOKENS_EXTRA: readonly string[] = [
  "filter",
];
