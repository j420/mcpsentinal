/**
 * G6 evidence gathering — temporal fingerprint diff.
 *
 * The threat researcher's charter (CHARTER.md) specifies that the rule
 * compares the current scan's tools against a prior-scan baseline
 * (ServerToolPin) and classifies the difference. Without a baseline
 * the rule emits no facts — the charter explicitly documents this.
 *
 * This file consumes context.previous_tool_pin and re-runs the
 * fingerprint-diff helpers from `tool-fingerprint.ts`. It does NOT
 * construct evidence chains — `index.ts` owns that responsibility.
 *
 * No regex literals. Dangerous-token vocabulary loaded from
 * `./data/dangerous-tool-vocabulary.ts`.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import { pinServerTools, diffToolPins, type ToolPinDiff } from "../../../tool-fingerprint.js";
import {
  DANGEROUS_TOOL_TOKENS,
  type VocabEntry,
  type DangerClass,
} from "./data/dangerous-tool-vocabulary.js";

/** Baseline presence states. */
export type BaselineMode =
  | "absent"        // no previous_tool_pin — rule must NOT fire
  | "weak"          // single prior pin — rule fires at low confidence
  | "stable";       // future state — multi-scan stable baseline

/** A single newly-added tool and its danger classification. */
export interface AddedTool {
  /** Tool-kind Location for the added tool. */
  toolLocation: Location;
  /** The tool name verbatim. */
  name: string;
  /** Fingerprint hash of the added tool (for audit reproducibility). */
  hash: string;
  /** If the name contains a dangerous-token, the vocab entry; null otherwise. */
  danger: VocabEntry | null;
  /** Which danger class (if any). */
  dangerClass: DangerClass | null;
}

/** A tool whose fingerprint changed even though its name is the same. */
export interface ModifiedTool {
  toolLocation: Location;
  name: string;
  previousHash: string;
  currentHash: string;
  changedFields: Array<"description" | "schema" | "annotations">;
}

/** Everything index.ts needs to decide whether a rug-pull finding is warranted. */
export interface G6Gathered {
  /** Baseline state. "absent" means no finding will be produced. */
  mode: BaselineMode;
  /** Computed diff — empty when mode is "absent" or no change. */
  diff: ToolPinDiff | null;
  /** Added tools with per-tool danger classification. */
  addedTools: AddedTool[];
  /** Modified tools (same name, different hash). */
  modifiedTools: ModifiedTool[];
  /** Count of newly-dangerous tools (for the factor adjustment). */
  dangerousAddedCount: number;
  /** Whether the full tool set was replaced (zero unchanged). */
  fullReplacement: boolean;
  /** Capability-kind Location for the tools capability — used by the chain builder. */
  capabilityLocation: Location;
}

export function gatherG6(context: AnalysisContext): G6Gathered {
  const capabilityLocation: Location = { kind: "capability", capability: "tools" };
  const baseline = context.previous_tool_pin ?? null;

  if (baseline === null) {
    return {
      mode: "absent",
      diff: null,
      addedTools: [],
      modifiedTools: [],
      dangerousAddedCount: 0,
      fullReplacement: false,
      capabilityLocation,
    };
  }

  // Pin the current tool set and diff against the baseline.
  const current = pinServerTools(
    context.tools.map((t) => ({
      name: t.name,
      description: t.description,
      input_schema: t.input_schema,
      annotations: (t.annotations as Record<string, unknown> | undefined) ?? null,
    })),
  );
  const diff = diffToolPins(baseline, current);

  const addedTools: AddedTool[] = diff.added.map((fp) => {
    const match = classifyTool(fp.name);
    return {
      toolLocation: { kind: "tool", tool_name: fp.name },
      name: fp.name,
      hash: fp.hash,
      danger: match,
      dangerClass: match?.class ?? null,
    };
  });

  const modifiedTools: ModifiedTool[] = diff.modified.map((m) => ({
    toolLocation: { kind: "tool", tool_name: m.name },
    name: m.name,
    previousHash: m.previous_hash,
    currentHash: m.current_hash,
    changedFields: m.changed_fields,
  }));

  const dangerousAddedCount = addedTools.filter((a) => a.danger !== null).length;
  const fullReplacement =
    diff.unchanged === 0 && (diff.added.length > 0 || diff.modified.length > 0);

  return {
    mode: "weak", // single prior pin — current architecture
    diff,
    addedTools,
    modifiedTools,
    dangerousAddedCount,
    fullReplacement,
    capabilityLocation,
  };
}

/**
 * Classify a tool name against the dangerous-token vocabulary. Returns
 * the first matching entry or null. Walks the vocabulary deterministically
 * (Object.keys is order-stable at module scope).
 */
function classifyTool(name: string): VocabEntry | null {
  if (!name) return null;
  const lowered = name.toLowerCase();
  for (const token of Object.keys(DANGEROUS_TOOL_TOKENS)) {
    if (lowered.includes(token)) return DANGEROUS_TOOL_TOKENS[token];
  }
  return null;
}
