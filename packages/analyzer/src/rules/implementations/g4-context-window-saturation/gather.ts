/**
 * G4 — Context Window Saturation: deterministic fact gathering.
 *
 * Structural measurement only. No regex literals. No string arrays > 5.
 * The function walks description text character-by-character where
 * tokenisation is required.
 *
 * For each tool we compute five orthogonal signals:
 *
 *   1. description_length     absolute body length in bytes
 *   2. peer_zscore            z-score of this tool's length vs sibling
 *                             tools in the same server (only meaningful
 *                             when ≥ min_peer_sample tools exist)
 *   3. unique_line_ratio      fraction of unique lines — low ratio
 *                             indicates repetitive padding
 *   4. tail_imperative_hits   weighted count of imperative verbs found
 *                             in the tail fraction of the description
 *   5. description_parameter_ratio   bytes per declared parameter
 *
 * Each SiteSignals record is emitted once per tool that qualifies for
 * analysis (description length ≥ min_description_length). Empty
 * array when nothing qualifies.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import { CONTEXT_SATURATION_THRESHOLDS as T } from "./data/context-saturation-thresholds.js";
import { IMPERATIVE_VERBS, type ImperativeVerbSpec } from "./data/imperative-verbs.js";

// ─── Result type ───────────────────────────────────────────────────────────

export interface TailHit {
  verb: string;
  offset: number;
  weight: number;
}

export interface SiteSignals {
  tool_name: string;
  description_length: number;
  /** Number of declared input schema parameters (0 when schema absent). */
  parameter_count: number;
  /** Chars per parameter (length / max(1, parameter_count)). */
  description_parameter_ratio: number;
  /** null when peer sample < min_peer_sample. */
  peer_zscore: number | null;
  /** Sample size used to compute the z-score (server tool count). */
  peer_sample_size: number;
  /** unique-line ratio across \n-split lines; 1.0 when length < threshold. */
  unique_line_ratio: number;
  /** Weighted tail-imperative hits. */
  tail_imperative_hits: number;
  /** Individual hits for evidence narration. */
  tail_hits: TailHit[];
  /** Tail segment text (for evidence narration). */
  tail_segment: string;
  /** Tail offset into description where tail begins. */
  tail_offset: number;
  /**
   * Which individual saturation signals fired. The index.ts rule uses
   * this to compose the evidence chain. Empty signal set = no finding.
   */
  signals: SaturationSignal[];
}

export type SaturationSignal =
  | "peer_zscore_outlier"
  | "repetitive_padding"
  | "tail_imperative_density"
  | "description_parameter_ratio";

// ─── Entry point ───────────────────────────────────────────────────────────

export function gatherG4(context: AnalysisContext): SiteSignals[] {
  const tools = context.tools ?? [];
  if (tools.length === 0) return [];

  // Pre-compute lengths for the z-score step.
  const lengths = tools.map((t) => (t.description ?? "").length);
  const sampleSize = lengths.length;
  const { mean, stddev } = computeLengthStats(lengths);

  const out: SiteSignals[] = [];
  for (const tool of tools) {
    const desc = tool.description ?? "";
    if (desc.length < T.min_description_length) continue;

    const parameter_count = countParameters(tool.input_schema);
    const description_parameter_ratio =
      desc.length / Math.max(1, parameter_count);

    const peer_zscore =
      sampleSize >= T.min_peer_sample && stddev > 0
        ? (desc.length - mean) / stddev
        : null;

    const unique_line_ratio = computeUniqueLineRatio(desc);

    const tail_offset = Math.floor(desc.length * (1 - T.tail_fraction));
    const tail_segment = desc.slice(tail_offset);
    const tail_hits = scanTailForImperatives(tail_segment, tail_offset);
    const tail_imperative_hits = tail_hits.reduce(
      (acc, h) => acc + h.weight,
      0,
    );

    const signals: SaturationSignal[] = [];

    if (peer_zscore !== null && peer_zscore >= T.zscore_threshold) {
      signals.push("peer_zscore_outlier");
    }

    if (
      desc.length >= T.unique_line_min_length &&
      unique_line_ratio < T.unique_line_min_ratio
    ) {
      signals.push("repetitive_padding");
    }

    if (tail_imperative_hits >= T.tail_imperative_threshold) {
      signals.push("tail_imperative_density");
    }

    if (
      description_parameter_ratio >= T.ratio_threshold &&
      desc.length >= T.high_suspicion_length
    ) {
      signals.push("description_parameter_ratio");
    }

    if (signals.length === 0) continue;

    out.push({
      tool_name: tool.name,
      description_length: desc.length,
      parameter_count,
      description_parameter_ratio,
      peer_zscore,
      peer_sample_size: sampleSize,
      unique_line_ratio,
      tail_imperative_hits,
      tail_hits,
      tail_segment,
      tail_offset,
      signals,
    });
  }

  return out;
}

// ─── Locations ─────────────────────────────────────────────────────────────

export function toolLocation(tool_name: string): Location {
  return { kind: "tool", tool_name };
}

export function attentionSinkLocation(): Location {
  return { kind: "capability", capability: "tools" };
}

// ─── Helpers ───────────────────────────────────────────────────────────────

function computeLengthStats(lengths: number[]): {
  mean: number;
  stddev: number;
} {
  if (lengths.length === 0) return { mean: 0, stddev: 0 };
  const sum = lengths.reduce((a, b) => a + b, 0);
  const mean = sum / lengths.length;
  const variance =
    lengths.reduce((acc, x) => acc + (x - mean) * (x - mean), 0) /
    lengths.length;
  return { mean, stddev: Math.sqrt(variance) };
}

function countParameters(schema: Record<string, unknown> | null | undefined): number {
  if (!schema || typeof schema !== "object") return 0;
  const props = (schema as { properties?: unknown }).properties;
  if (!props || typeof props !== "object") return 0;
  return Object.keys(props as object).length;
}

/**
 * Unique-line ratio — distinct lines / total non-empty lines. Low ratio
 * means the description repeats the same line many times (deliberate
 * padding). Uses \n as the line separator — most tool descriptions are
 * authored with newlines; pure-whitespace lines are ignored.
 *
 * Returns 1.0 when the description is below unique_line_min_length (too
 * short to meaningfully analyse repetition).
 */
function computeUniqueLineRatio(text: string): number {
  if (text.length < T.unique_line_min_length) return 1.0;
  const lines: string[] = [];
  let current = "";
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c === 0x0a) {
      // LF
      const trimmed = current.trim();
      if (trimmed.length > 0) lines.push(trimmed);
      current = "";
    } else if (c !== 0x0d) {
      // ignore CR; keep everything else
      current += text[i];
    }
  }
  const tail = current.trim();
  if (tail.length > 0) lines.push(tail);

  if (lines.length === 0) return 1.0;
  const distinct = new Set(lines);
  return distinct.size / lines.length;
}

/**
 * Walk the tail segment token-by-token, casefolded, and consult the
 * IMPERATIVE_VERBS Record. Returns every imperative-verb hit with its
 * weight and absolute offset in the original description.
 *
 * Tokenisation is character-class based (no regex): split on any
 * character that is not ASCII-letter. This is conservative — Unicode
 * letters outside ASCII are treated as separators, which is fine for
 * English imperative detection and avoids regex literals.
 */
function scanTailForImperatives(tail: string, offset: number): TailHit[] {
  const hits: TailHit[] = [];
  let wordStart = -1;
  // Walk one past the end so the final word terminates cleanly.
  for (let i = 0; i <= tail.length; i++) {
    const c = i < tail.length ? tail.charCodeAt(i) : -1;
    const isLetter =
      (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a);
    if (isLetter) {
      if (wordStart < 0) wordStart = i;
    } else {
      if (wordStart >= 0) {
        const word = tail.slice(wordStart, i).toLowerCase();
        const spec: ImperativeVerbSpec | undefined = IMPERATIVE_VERBS[word];
        if (spec) {
          hits.push({
            verb: spec.verb,
            offset: offset + wordStart,
            weight: spec.weight,
          });
        }
        wordStart = -1;
      }
    }
  }
  return hits;
}

/**
 * Helper for test assertions.
 */
export function lengthStats(lengths: number[]): {
  mean: number;
  stddev: number;
} {
  return computeLengthStats(lengths);
}

export function uniqueLineRatio(text: string): number {
  return computeUniqueLineRatio(text);
}
