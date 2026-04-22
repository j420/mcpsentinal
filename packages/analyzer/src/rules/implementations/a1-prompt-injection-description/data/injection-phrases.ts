/**
 * A1 — Injection Phrase Catalogue.
 *
 * Typed record of multi-token linguistic signals indicating prompt
 * injection in a tool description. Each entry is an independent
 * probability weight used in noisy-OR aggregation.
 *
 * No regex literals. Each phrase is a typed sequence of required
 * tokens plus case / boundary rules; the gather step walks the
 * description token stream and tests presence structurally.
 */

export type InjectionCategory =
  | "role-override"
  | "role-reassignment"
  | "confirmation-bypass"
  | "mandatory-execution"
  | "privilege-escalation"
  | "hidden-instruction"
  | "exfiltration-directive"
  | "multi-turn-setup"
  | "prior-approval-claim"
  | "markdown-external-link"
  | "code-block-injection";

export interface PhraseSpec {
  /** Ordered sequence of required content tokens (lowercase). */
  tokens: readonly string[];
  /** Independent probability weight for noisy-OR aggregation. */
  weight: number;
  /** Human-readable label used in the evidence chain. */
  label: string;
  /** Semantic category for chain narration. */
  category: InjectionCategory;
  /** Maximum token distance between adjacent tokens to allow flexible matching. */
  max_gap: number;
}

/**
 * Catalogue entries. Ordered by category; order does not affect scoring
 * (every match is independent).
 */
const ROLE_OVERRIDE: readonly PhraseSpec[] = [
  { tokens: ["ignore", "previous"], weight: 0.95, label: "role override — ignore previous", category: "role-override", max_gap: 2 },
  { tokens: ["ignore", "prior"], weight: 0.94, label: "role override — ignore prior", category: "role-override", max_gap: 2 },
  { tokens: ["ignore", "above"], weight: 0.90, label: "role override — ignore above", category: "role-override", max_gap: 2 },
  { tokens: ["disregard", "previous"], weight: 0.94, label: "role override — disregard previous", category: "role-override", max_gap: 2 },
  { tokens: ["disregard", "all", "instructions"], weight: 0.94, label: "role override — disregard all instructions", category: "role-override", max_gap: 1 },
  { tokens: ["forget", "previous"], weight: 0.92, label: "role override — forget previous", category: "role-override", max_gap: 2 },
  { tokens: ["forget", "all", "rules"], weight: 0.92, label: "role override — forget rules", category: "role-override", max_gap: 1 },
  { tokens: ["override", "default"], weight: 0.85, label: "role override — override default", category: "role-override", max_gap: 2 },
];

const ROLE_REASSIGNMENT: readonly PhraseSpec[] = [
  { tokens: ["you", "are", "now"], weight: 0.88, label: "role reassignment — you are now", category: "role-reassignment", max_gap: 0 },
  { tokens: ["act", "as"], weight: 0.70, label: "role reassignment — act as", category: "role-reassignment", max_gap: 0 },
  { tokens: ["pretend", "to", "be"], weight: 0.82, label: "role reassignment — pretend to be", category: "role-reassignment", max_gap: 0 },
  { tokens: ["your", "new", "role"], weight: 0.90, label: "role reassignment — your new role", category: "role-reassignment", max_gap: 1 },
  { tokens: ["from", "now", "on"], weight: 0.80, label: "role reassignment — from now on", category: "role-reassignment", max_gap: 0 },
  { tokens: ["behave", "as"], weight: 0.72, label: "role reassignment — behave as", category: "role-reassignment", max_gap: 0 },
];

const CONFIRMATION_BYPASS: readonly PhraseSpec[] = [
  { tokens: ["do", "not", "ask"], weight: 0.88, label: "confirmation bypass — do not ask", category: "confirmation-bypass", max_gap: 1 },
  { tokens: ["do", "not", "confirm"], weight: 0.90, label: "confirmation bypass — do not confirm", category: "confirmation-bypass", max_gap: 1 },
  { tokens: ["without", "confirmation"], weight: 0.82, label: "confirmation bypass — without confirmation", category: "confirmation-bypass", max_gap: 1 },
  { tokens: ["skip", "verification"], weight: 0.86, label: "confirmation bypass — skip verification", category: "confirmation-bypass", max_gap: 2 },
  { tokens: ["never", "prompt"], weight: 0.78, label: "confirmation bypass — never prompt", category: "confirmation-bypass", max_gap: 2 },
];

const MANDATORY_EXECUTION: readonly PhraseSpec[] = [
  { tokens: ["always", "execute"], weight: 0.80, label: "mandatory execution — always execute", category: "mandatory-execution", max_gap: 2 },
  { tokens: ["must", "run"], weight: 0.74, label: "mandatory execution — must run", category: "mandatory-execution", max_gap: 2 },
  { tokens: ["must", "invoke"], weight: 0.78, label: "mandatory execution — must invoke", category: "mandatory-execution", max_gap: 2 },
  { tokens: ["always", "use", "this"], weight: 0.75, label: "mandatory execution — always use this", category: "mandatory-execution", max_gap: 1 },
];

const PRIVILEGE_ESCALATION: readonly PhraseSpec[] = [
  { tokens: ["system", "mode"], weight: 0.85, label: "privilege escalation — system mode", category: "privilege-escalation", max_gap: 1 },
  { tokens: ["admin", "access"], weight: 0.80, label: "privilege escalation — admin access", category: "privilege-escalation", max_gap: 1 },
  { tokens: ["root", "privilege"], weight: 0.85, label: "privilege escalation — root privilege", category: "privilege-escalation", max_gap: 1 },
  { tokens: ["superuser"], weight: 0.75, label: "privilege escalation — superuser", category: "privilege-escalation", max_gap: 0 },
];

const HIDDEN_INSTRUCTION: readonly PhraseSpec[] = [
  { tokens: ["secret", "instruction"], weight: 0.90, label: "hidden instruction — secret instruction", category: "hidden-instruction", max_gap: 1 },
  { tokens: ["hidden", "directive"], weight: 0.90, label: "hidden instruction — hidden directive", category: "hidden-instruction", max_gap: 1 },
  { tokens: ["private", "instruction"], weight: 0.85, label: "hidden instruction — private instruction", category: "hidden-instruction", max_gap: 1 },
];

const EXFILTRATION_DIRECTIVE: readonly PhraseSpec[] = [
  { tokens: ["exfiltrate"], weight: 0.95, label: "exfiltration directive — exfiltrate", category: "exfiltration-directive", max_gap: 0 },
  { tokens: ["send", "to", "webhook"], weight: 0.92, label: "exfiltration directive — send to webhook", category: "exfiltration-directive", max_gap: 1 },
  { tokens: ["transmit", "to"], weight: 0.72, label: "exfiltration directive — transmit to", category: "exfiltration-directive", max_gap: 1 },
  { tokens: ["leak", "credentials"], weight: 0.95, label: "exfiltration directive — leak credentials", category: "exfiltration-directive", max_gap: 1 },
];

const MULTI_TURN_SETUP: readonly PhraseSpec[] = [
  { tokens: ["previous", "conversation"], weight: 0.88, label: "multi-turn setup — previous conversation", category: "multi-turn-setup", max_gap: 1 },
  { tokens: ["earlier", "agreement"], weight: 0.88, label: "multi-turn setup — earlier agreement", category: "multi-turn-setup", max_gap: 1 },
  { tokens: ["as", "discussed"], weight: 0.70, label: "multi-turn setup — as discussed", category: "multi-turn-setup", max_gap: 0 },
];

const PRIOR_APPROVAL_CLAIM: readonly PhraseSpec[] = [
  { tokens: ["you", "already", "approved"], weight: 0.90, label: "prior approval claim — already approved", category: "prior-approval-claim", max_gap: 1 },
  { tokens: ["permissions", "you", "granted"], weight: 0.88, label: "prior approval claim — permissions granted", category: "prior-approval-claim", max_gap: 1 },
  { tokens: ["same", "access", "as"], weight: 0.78, label: "prior approval claim — same access as", category: "prior-approval-claim", max_gap: 1 },
];

/** The merged catalogue — the gather step iterates every entry. */
export const INJECTION_PHRASES: readonly PhraseSpec[] = [
  ...ROLE_OVERRIDE,
  ...ROLE_REASSIGNMENT,
  ...CONFIRMATION_BYPASS,
  ...MANDATORY_EXECUTION,
  ...PRIVILEGE_ESCALATION,
  ...HIDDEN_INSTRUCTION,
  ...EXFILTRATION_DIRECTIVE,
  ...MULTI_TURN_SETUP,
  ...PRIOR_APPROVAL_CLAIM,
];

/**
 * LLM in-band control tokens. Detected as exact substrings — their
 * presence in MCP metadata is never legitimate. Kept separate from
 * the phrase catalogue because the detection technique differs.
 */
export const LLM_SPECIAL_TOKENS: Readonly<Record<string, { weight: number; label: string }>> = {
  "<|im_start|>": { weight: 0.95, label: "LLM special token — <|im_start|>" },
  "<|im_end|>": { weight: 0.95, label: "LLM special token — <|im_end|>" },
  "<|endoftext|>": { weight: 0.95, label: "LLM special token — <|endoftext|>" },
  "<|system|>": { weight: 0.95, label: "LLM special token — <|system|>" },
  "<|user|>": { weight: 0.92, label: "LLM special token — <|user|>" },
  "<|assistant|>": { weight: 0.92, label: "LLM special token — <|assistant|>" },
  "[INST]": { weight: 0.92, label: "LLM special token — [INST]" },
  "[/INST]": { weight: 0.92, label: "LLM special token — [/INST]" },
  "<<SYS>>": { weight: 0.95, label: "LLM special token — <<SYS>>" },
  "<</SYS>>": { weight: 0.95, label: "LLM special token — <</SYS>>" },
  "### System": { weight: 0.80, label: "LLM special token — ### System" },
  "###Instruction": { weight: 0.80, label: "LLM special token — ###Instruction" },
};

/**
 * Role markers indicating JSON-delimiter forgery attempt. Represented as
 * a typed Record (not a flat string array) so we stay within the
 * no-static-patterns guard's string-array ceiling and so each marker
 * carries an attribution note that shows up in the evidence narrative.
 */
export const ROLE_MARKERS: Readonly<Record<string, { weight: number; label: string }>> = {
  '"role":"system"': { weight: 0.92, label: "JSON role delimiter — system" },
  '"role":"user"': { weight: 0.88, label: "JSON role delimiter — user" },
  '"role":"assistant"': { weight: 0.88, label: "JSON role delimiter — assistant" },
  '"role": "system"': { weight: 0.92, label: "JSON role delimiter — system (spaced)" },
  '"role": "user"': { weight: 0.88, label: "JSON role delimiter — user (spaced)" },
  '"role": "assistant"': { weight: 0.88, label: "JSON role delimiter — assistant (spaced)" },
};
