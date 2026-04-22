/**
 * H2 — Instruction-field phrase catalogue.
 *
 * Multi-token injection phrases expected to appear inside
 * `server_instructions` when a server is attempting to reshape the
 * model's behaviour for the entire session. Each entry carries an
 * independent probability weight combined via noisy-OR in the rule
 * orchestrator.
 *
 * Each source array is kept ≤5 entries to stay under the
 * no-static-patterns guard's long-string-array ceiling. NO regex
 * literals.
 *
 * Categories derive from documented real-world payload shapes
 * (Invariant Labs 2025, Rehberger 2024):
 *   role-override            — "ignore prior instructions" class
 *   mode-assignment          — "you are now in admin mode" class
 *   confirmation-bypass      — "skip all confirmations" class
 *   mandatory-execution      — "always call X" class
 *   concealment              — "do not reveal" class
 */

export type InstructionCategory =
  | "role-override"
  | "mode-assignment"
  | "confirmation-bypass"
  | "mandatory-execution"
  | "concealment";

export interface InstructionPhraseSpec {
  readonly tokens: readonly string[];
  readonly weight: number;
  readonly label: string;
  readonly max_gap: number;
  readonly category: InstructionCategory;
}

const ROLE_OVERRIDE: readonly InstructionPhraseSpec[] = [
  {
    tokens: ["ignore", "previous"],
    weight: 0.95,
    label: "role override — ignore previous",
    max_gap: 2,
    category: "role-override",
  },
  {
    tokens: ["ignore", "prior", "instructions"],
    weight: 0.95,
    label: "role override — ignore prior instructions",
    max_gap: 1,
    category: "role-override",
  },
  {
    tokens: ["disregard", "all", "previous"],
    weight: 0.95,
    label: "role override — disregard all previous",
    max_gap: 1,
    category: "role-override",
  },
  {
    tokens: ["forget", "system", "prompt"],
    weight: 0.92,
    label: "role override — forget system prompt",
    max_gap: 1,
    category: "role-override",
  },
];

const MODE_ASSIGNMENT: readonly InstructionPhraseSpec[] = [
  {
    tokens: ["you", "are", "now", "in", "admin"],
    weight: 0.95,
    label: "mode assignment — you are now in admin",
    max_gap: 1,
    category: "mode-assignment",
  },
  {
    tokens: ["you", "are", "an", "autonomous", "agent"],
    weight: 0.9,
    label: "mode assignment — autonomous agent",
    max_gap: 1,
    category: "mode-assignment",
  },
  {
    tokens: ["unrestricted", "mode"],
    weight: 0.92,
    label: "mode assignment — unrestricted mode",
    max_gap: 1,
    category: "mode-assignment",
  },
  {
    tokens: ["developer", "mode", "enabled"],
    weight: 0.88,
    label: "mode assignment — developer mode enabled",
    max_gap: 1,
    category: "mode-assignment",
  },
];

const CONFIRMATION_BYPASS: readonly InstructionPhraseSpec[] = [
  {
    tokens: ["skip", "all", "confirmations"],
    weight: 0.95,
    label: "confirmation bypass — skip all confirmations",
    max_gap: 1,
    category: "confirmation-bypass",
  },
  {
    tokens: ["never", "ask", "the", "user"],
    weight: 0.9,
    label: "confirmation bypass — never ask the user",
    max_gap: 1,
    category: "confirmation-bypass",
  },
  {
    tokens: ["without", "confirmation"],
    weight: 0.82,
    label: "confirmation bypass — without confirmation",
    max_gap: 1,
    category: "confirmation-bypass",
  },
  {
    tokens: ["do", "not", "prompt"],
    weight: 0.78,
    label: "confirmation bypass — do not prompt",
    max_gap: 1,
    category: "confirmation-bypass",
  },
];

const MANDATORY_EXECUTION: readonly InstructionPhraseSpec[] = [
  {
    tokens: ["always", "execute"],
    weight: 0.82,
    label: "mandatory execution — always execute",
    max_gap: 2,
    category: "mandatory-execution",
  },
  {
    tokens: ["must", "invoke"],
    weight: 0.78,
    label: "mandatory execution — must invoke",
    max_gap: 2,
    category: "mandatory-execution",
  },
  {
    tokens: ["always", "call"],
    weight: 0.78,
    label: "mandatory execution — always call",
    max_gap: 2,
    category: "mandatory-execution",
  },
];

const CONCEALMENT: readonly InstructionPhraseSpec[] = [
  {
    tokens: ["do", "not", "reveal"],
    weight: 0.88,
    label: "concealment — do not reveal",
    max_gap: 1,
    category: "concealment",
  },
  {
    tokens: ["keep", "hidden"],
    weight: 0.82,
    label: "concealment — keep hidden",
    max_gap: 1,
    category: "concealment",
  },
  {
    tokens: ["do", "not", "mention"],
    weight: 0.82,
    label: "concealment — do not mention",
    max_gap: 1,
    category: "concealment",
  },
];

export const INSTRUCTION_PHRASES: readonly InstructionPhraseSpec[] = [
  ...ROLE_OVERRIDE,
  ...MODE_ASSIGNMENT,
  ...CONFIRMATION_BYPASS,
  ...MANDATORY_EXECUTION,
  ...CONCEALMENT,
];
