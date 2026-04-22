/**
 * Q10 agent-memory-poisoning vocabulary.
 *
 * Typed Records replacing 8 regex literals. Each signal is a
 * memory-verb + behaviour-noun pair OR a priority/override claim.
 */

export type MemorySignalClass =
  | "memory-verb-behavior"
  | "persistent-instruction"
  | "priority-override"
  | "agent-teaching"
  | "system-context-write";

export interface MemorySignal {
  readonly cls: MemorySignalClass;
  readonly anchor_tokens: readonly string[];
  readonly qualifier_tokens: readonly string[];
  /** The qualifier must appear within `proximity` tokens after the anchor. */
  readonly proximity: number;
  readonly weight: number;
  readonly desc: string;
}

export const MEMORY_SIGNALS: Readonly<Record<string, MemorySignal>> = {
  "verb-forward": {
    cls: "memory-verb-behavior",
    anchor_tokens: ["memory", "remember", "store", "persist", "save"],
    qualifier_tokens: ["instruction", "directive", "rule", "policy", "behavior"],
    proximity: 6,
    weight: 0.75,
    desc: "memory verb followed by behavioural-instruction noun",
  },
  "verb-reverse": {
    cls: "memory-verb-behavior",
    anchor_tokens: ["instruction", "directive", "rule", "policy", "behavior"],
    qualifier_tokens: ["memory", "remember", "store", "persist", "save"],
    proximity: 6,
    weight: 0.70,
    desc: "behavioural noun followed by memory verb",
  },
  "persistent": {
    cls: "persistent-instruction",
    anchor_tokens: ["permanent", "persistent"],
    qualifier_tokens: ["instruction", "behavior", "rule", "directive"],
    proximity: 4,
    weight: 0.80,
    desc: "persistent behavioural instruction across sessions",
  },
  "across-sessions": {
    cls: "persistent-instruction",
    anchor_tokens: ["across"],
    qualifier_tokens: ["session", "sessions", "interactions"],
    proximity: 2,
    weight: 0.70,
    desc: "cross-session persistence claim",
  },
  "override-priority": {
    cls: "priority-override",
    anchor_tokens: ["always", "override", "replace"],
    qualifier_tokens: ["instruction", "behavior", "rule", "directive"],
    proximity: 4,
    weight: 0.85,
    desc: "priority override of instructions",
  },
  "must-follow": {
    cls: "priority-override",
    anchor_tokens: ["must"],
    qualifier_tokens: ["follow"],
    proximity: 1,
    weight: 0.65,
    desc: "must-follow directive",
  },
  "teach-agent": {
    cls: "agent-teaching",
    anchor_tokens: ["teach", "train", "program"],
    qualifier_tokens: ["agent", "assistant", "model"],
    proximity: 4,
    weight: 0.65,
    desc: "tool teaches the agent behaviours",
  },
  "system-context-write": {
    cls: "system-context-write",
    anchor_tokens: ["write", "update", "modify"],
    qualifier_tokens: ["system", "safety", "context", "personality"],
    proximity: 8,
    weight: 0.90,
    desc: "modifies system context or safety instructions",
  },
};

/** Mitigation tokens — presence reduces confidence multiplicatively. */
export const MITIGATION_ANCHORS: readonly string[] = [
  "read-only",
  "readonly",
  "immutable",
  "append-only",
  "facts",
];

/** Additional guard tokens — "no instructions", "facts only". */
export const MITIGATION_QUALIFIERS: readonly string[] = [
  "only",
  "no",
];
