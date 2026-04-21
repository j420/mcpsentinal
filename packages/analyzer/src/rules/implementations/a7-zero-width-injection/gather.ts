/**
 * A7 — Gather phase.
 *
 * Walk every tool name, description, and parameter description codepoint by
 * codepoint. Record every invisible/zero-width/bidi/tag codepoint observed,
 * along with its class and position. Extract any hidden ASCII message that a
 * sequence of tag codepoints decodes to.
 *
 * No regex literals. All detection is integer-range arithmetic on Unicode
 * codepoints.
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  INVISIBLE_RANGES,
  EMOJI_RANGES,
  type InvisibleClass,
  type InvisibleRange,
} from "./data/invisible-codepoints.js";

/** One invisible codepoint observed at a specific position in a field */
export interface InvisibleHit {
  codepoint: number;
  label: string;
  position: number;
  class: InvisibleClass;
  range_name: string;
  range_description: string;
}

/** Aggregate analysis of a single field */
export interface A7FieldAnalysis {
  value: string;
  hits: InvisibleHit[];
  /** Classes seen (deduplicated) — used for confidence + rendering */
  classes_seen: InvisibleClass[];
  /** If tag characters were present, the decoded ASCII message */
  hidden_tag_message: string | null;
  /** Total codepoints in the field */
  codepoint_count: number;
}

export interface A7ParamAnalysis extends A7FieldAnalysis {
  parameter_name: string;
}

export interface A7ToolGather {
  tool_name: string;
  tool_index: number;
  name_analysis: A7FieldAnalysis;
  description_analysis: A7FieldAnalysis | null;
  parameter_analyses: A7ParamAnalysis[];
}

export interface A7Gather {
  tools: A7ToolGather[];
}

// ───────────────────────── primitives ────────────────────────

function labelFor(cp: number): string {
  return `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`;
}

function inAnyRange(cp: number, ranges: ReadonlyArray<readonly [number, number]>): boolean {
  for (const [s, e] of ranges) if (cp >= s && cp <= e) return true;
  return false;
}

function isEmojiCodepoint(cp: number): boolean {
  return inAnyRange(cp, EMOJI_RANGES);
}

/** Which InvisibleRange does this codepoint belong to, if any? */
function invisibleRangeOf(cp: number): InvisibleRange | null {
  for (const key of Object.keys(INVISIBLE_RANGES)) {
    const r = INVISIBLE_RANGES[key];
    if (cp >= r.start && cp <= r.end) return r;
  }
  return null;
}

/**
 * Decide whether to suppress a ZWJ / ZWNJ that is flanked by emoji on both sides.
 * That is the Unicode-blessed ligature use case (flag, family, skin tone).
 *
 * `cp` is the joiner codepoint, `prev` is the codepoint immediately before it
 * in the string, `next` is the codepoint immediately after. Either may be -1
 * if we are at a field boundary.
 */
function isLegitimateEmojiJoiner(cp: number, prev: number, next: number): boolean {
  if (cp !== 0x200d && cp !== 0x200c) return false;
  if (prev < 0 || next < 0) return false;
  return isEmojiCodepoint(prev) && isEmojiCodepoint(next);
}

// ──────────────────────── field analysis ────────────────────

export function analyseField(value: string, fieldKind: "name" | "description"): A7FieldAnalysis {
  const hits: InvisibleHit[] = [];
  const classes = new Set<InvisibleClass>();
  const tagChars: number[] = [];

  // Pre-pass: convert the string to an array of codepoints + positions so we
  // can look at neighbours without re-decoding.
  const cps: Array<{ cp: number; position: number }> = [];
  for (let i = 0; i < value.length; i++) {
    const cp = value.codePointAt(i)!;
    cps.push({ cp, position: i });
    if (cp > 0xffff) i++;
  }

  for (let k = 0; k < cps.length; k++) {
    const { cp, position } = cps[k];
    const prev = k > 0 ? cps[k - 1].cp : -1;
    const next = k + 1 < cps.length ? cps[k + 1].cp : -1;

    const range = invisibleRangeOf(cp);
    if (!range) continue;

    // Suppression rules:
    //   - BOM at the very start of a field is legitimate (byte-order mark).
    //     Anywhere else it is suspicious.
    if (cp === 0xfeff && position === 0) continue;
    //   - ZWJ / ZWNJ between two emoji codepoints is a legitimate emoji sequence.
    if (isLegitimateEmojiJoiner(cp, prev, next)) continue;
    //   - Variation selectors immediately AFTER an emoji codepoint are
    //     legitimate emoji presentation selectors (U+FE0E text, U+FE0F emoji).
    //     Applied for tool DESCRIPTIONS only; for tool NAMES, variation selectors
    //     are always suspicious since identifiers should not carry them.
    if (
      range.class === "variation-selector" &&
      fieldKind === "description" &&
      prev >= 0 &&
      isEmojiCodepoint(prev)
    ) {
      continue;
    }

    hits.push({
      codepoint: cp,
      label: labelFor(cp),
      position,
      class: range.class,
      range_name: range.name,
      range_description: range.description,
    });
    classes.add(range.class);

    // Collect tag characters for hidden-message decoding
    if (range.class === "tag-character" && cp >= 0xe0020 && cp <= 0xe007e) {
      tagChars.push(cp - 0xe0000); // map back to ASCII range
    }
  }

  const hiddenMessage = tagChars.length >= 3 ? String.fromCharCode(...tagChars) : null;

  return {
    value,
    hits,
    classes_seen: Array.from(classes),
    hidden_tag_message: hiddenMessage,
    codepoint_count: cps.length,
  };
}

// ──────────────────────── context-level ─────────────────────

export function gather(context: AnalysisContext): A7Gather {
  const tools: A7ToolGather[] = [];

  for (let idx = 0; idx < context.tools.length; idx++) {
    const tool = context.tools[idx];

    const name_analysis = analyseField(tool.name, "name");
    const description_analysis = tool.description
      ? analyseField(tool.description, "description")
      : null;

    const parameter_analyses: A7ParamAnalysis[] = [];
    if (tool.input_schema && typeof tool.input_schema === "object") {
      const props = (tool.input_schema as { properties?: Record<string, unknown> }).properties;
      if (props && typeof props === "object") {
        for (const paramName of Object.keys(props)) {
          const paramDef = props[paramName] as { description?: unknown } | undefined;
          const desc = paramDef && typeof paramDef.description === "string" ? paramDef.description : "";
          if (!desc) continue;
          const a = analyseField(desc, "description");
          if (a.hits.length > 0) {
            parameter_analyses.push({ ...a, parameter_name: paramName });
          }
        }
      }
    }

    tools.push({
      tool_name: tool.name,
      tool_index: idx,
      name_analysis,
      description_analysis,
      parameter_analyses,
    });
  }

  return { tools };
}
