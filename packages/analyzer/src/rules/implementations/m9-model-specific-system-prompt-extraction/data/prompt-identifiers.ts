/**
 * M9 — Vocabulary for system-prompt-leak detection.
 */

export interface PromptIdent {
  readonly fragment: string;
  readonly label: string;
  /** 1 = high specificity (exact prompt token), 0.6 = medium, 0.3 = low. */
  readonly specificity: number;
}

export const PROMPT_IDENTIFIERS: Readonly<Record<string, PromptIdent>> = {
  system_prompt: {
    fragment: "system_prompt",
    label: "system_prompt variable",
    specificity: 1.0,
  },
  systemprompt: {
    fragment: "systemprompt",
    label: "systemPrompt variable",
    specificity: 1.0,
  },
  system_message: {
    fragment: "system_message",
    label: "system_message variable",
    specificity: 0.9,
  },
  systemmessage: {
    fragment: "systemmessage",
    label: "systemMessage variable",
    specificity: 0.9,
  },
  initial_prompt: {
    fragment: "initial_prompt",
    label: "initial_prompt variable",
    specificity: 0.9,
  },
  initial_instructions: {
    fragment: "initial_instructions",
    label: "initial_instructions variable",
    specificity: 0.85,
  },
  system_instructions: {
    fragment: "system_instructions",
    label: "system_instructions variable",
    specificity: 0.95,
  },
};

/** Return-shaped call / statement fragments. */
export const RETURN_SHAPED: Readonly<Record<string, string>> = {
  return: "return statement",
  res_send: "res.send",
  res_json: "res.json",
  res_end: "res.end",
  reply: "reply()",
  respond: "respond()",
};

/** Dev-mode gate keywords. */
export const DEV_GATE_KEYWORDS: Readonly<Record<string, string>> = {
  debug: "debug flag",
  devmode: "devmode flag",
  is_debug: "is_debug flag",
  process_env_debug: "process.env.DEBUG",
  admin: "admin gate",
  internal: "internal-only gate",
};

export const M9_CONFIDENCE_CAP = 0.8;
export const M9_GATE_WINDOW_LINES = 5;
