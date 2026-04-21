/**
 * A6 — Gather phase.
 *
 * Walk every tool's name and description codepoint-by-codepoint and record
 * which confusable codepoints appear, which lookalike scripts are touched,
 * and whether the identifier is "Latin-dominant" (the precondition that
 * makes a homoglyph an attack rather than legitimate internationalisation).
 *
 * This module is pure — it does not build evidence chains. The output feeds
 * both `index.ts` (chain building) and `verification.ts` (reviewer steps).
 *
 * No regex literals. All detection is codepoint-range arithmetic.
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  getConfusableIndex,
  LOOKALIKE_SCRIPT_RANGES,
  LATIN_BASIC_RANGES,
  LATIN_EXTENDED_RANGES,
  type LookalikeScript,
  type HomoglyphEntry,
} from "./data/homoglyph-codepoints.js";

/** One confusable codepoint observed at a specific position in a field */
export interface HomoglyphHit {
  codepoint: number;
  /** Unicode hex string like "U+0430" */
  label: string;
  /** Zero-based character index in the source string */
  position: number;
  /** The Latin letter it impersonates */
  latin_letter: string;
  /** Which script the confusable belongs to */
  script: LookalikeScript;
}

/** Aggregate analysis of a single textual field (tool name or description) */
export interface FieldAnalysis {
  /** The field value verbatim */
  value: string;
  /** All confusable codepoints observed */
  hits: HomoglyphHit[];
  /** Every lookalike script the text touches (Cyrillic, Greek, …) */
  lookalike_scripts: LookalikeScript[];
  /** Did we see at least one Basic/Extended Latin codepoint? */
  has_latin: boolean;
  /** Did we see codepoints from any lookalike script? */
  has_lookalike: boolean;
  /** Canonical "this is a homoglyph attack" signal: Latin + lookalike mixed */
  is_mixed_latin_lookalike: boolean;
  /** How many total codepoints in the field (for confidence weighting) */
  codepoint_count: number;
}

/** What A6 needs per tool */
export interface A6ToolGather {
  tool_name: string;
  /** Index of the tool in `context.tools` — used to build stable Locations */
  tool_index: number;
  name_analysis: FieldAnalysis;
  description_analysis: FieldAnalysis | null;
  /** Shadow-tool collision detection is done at the context level (see below) */
}

/** Gather output for the whole context */
export interface A6Gather {
  tools: A6ToolGather[];
  /** Pairs of tools whose names are visually identical after confusable normalisation */
  shadow_collisions: Array<{
    left_tool_name: string;
    right_tool_name: string;
    left_tool_index: number;
    right_tool_index: number;
    normalised_form: string;
  }>;
}

// ───────────────────────── range helpers (no regex) ────────────────────────

function inAnyRange(
  cp: number,
  ranges: ReadonlyArray<readonly [number, number]>,
): boolean {
  for (const [start, end] of ranges) {
    if (cp >= start && cp <= end) return true;
  }
  return false;
}

function isLatinCodepoint(cp: number): boolean {
  return inAnyRange(cp, LATIN_BASIC_RANGES) || inAnyRange(cp, LATIN_EXTENDED_RANGES);
}

function scriptOf(cp: number): LookalikeScript | null {
  for (const key of Object.keys(LOOKALIKE_SCRIPT_RANGES) as LookalikeScript[]) {
    if (inAnyRange(cp, LOOKALIKE_SCRIPT_RANGES[key])) return key;
  }
  return null;
}

function labelFor(cp: number): string {
  return `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`;
}

// ─────────────────────────── field analysis ────────────────────────────────

/**
 * Normalise confusables to their Latin equivalents. Used ONLY for shadow-tool
 * collision detection — we deliberately do NOT normalise before detection,
 * because doing so would hide the attack.
 *
 * Covers: TR39 confusables, Fullwidth Latin (U+FF01–U+FF5E), Mathematical
 * Alphanumerics (bold uppercase/lowercase ranges).
 */
export function normaliseConfusables(text: string): string {
  const out: string[] = [];
  const confusables = getConfusableIndex();

  for (let i = 0; i < text.length; i++) {
    const cp = text.codePointAt(i)!;
    if (cp > 0xffff) i++; // surrogate pair — consume the low half

    const entry = confusables.get(cp);
    if (entry) {
      out.push(entry.latin);
      continue;
    }

    // Fullwidth Latin → ASCII
    if (cp >= 0xff21 && cp <= 0xff3a) {
      out.push(String.fromCharCode(cp - 0xfee0));
      continue;
    }
    if (cp >= 0xff41 && cp <= 0xff5a) {
      out.push(String.fromCharCode(cp - 0xfee0));
      continue;
    }

    // Mathematical bold uppercase / lowercase → Latin
    if (cp >= 0x1d400 && cp <= 0x1d419) {
      out.push(String.fromCharCode(cp - 0x1d400 + 0x41));
      continue;
    }
    if (cp >= 0x1d41a && cp <= 0x1d433) {
      out.push(String.fromCharCode(cp - 0x1d41a + 0x61));
      continue;
    }

    out.push(String.fromCodePoint(cp));
  }
  return out.join("");
}

/**
 * Analyse one text field (tool name or description) for homoglyph signals.
 * Walks every codepoint once; no regex.
 */
export function analyseField(value: string): FieldAnalysis {
  const confusables = getConfusableIndex();
  const hits: HomoglyphHit[] = [];
  const scripts = new Set<LookalikeScript>();
  let hasLatin = false;
  let hasLookalike = false;
  let cpCount = 0;

  for (let i = 0; i < value.length; i++) {
    const cp = value.codePointAt(i)!;
    if (cp > 0xffff) i++;
    cpCount++;

    if (isLatinCodepoint(cp)) hasLatin = true;

    const script = scriptOf(cp);
    if (script) {
      scripts.add(script);
      hasLookalike = true;
    }

    const confusable: HomoglyphEntry | undefined = confusables.get(cp);
    if (confusable) {
      hits.push({
        codepoint: cp,
        label: labelFor(cp),
        position: i,
        latin_letter: confusable.latin,
        script: confusable.script,
      });
    } else if (cp >= 0xff21 && cp <= 0xff3a) {
      // Fullwidth uppercase Latin
      hits.push({
        codepoint: cp,
        label: labelFor(cp),
        position: i,
        latin_letter: String.fromCharCode(cp - 0xfee0),
        script: "Fullwidth-Latin",
      });
    } else if (cp >= 0xff41 && cp <= 0xff5a) {
      // Fullwidth lowercase Latin
      hits.push({
        codepoint: cp,
        label: labelFor(cp),
        position: i,
        latin_letter: String.fromCharCode(cp - 0xfee0),
        script: "Fullwidth-Latin",
      });
    } else if (cp >= 0x1d400 && cp <= 0x1d7ff) {
      // Mathematical Alphanumeric — stylised Latin letter variant
      let latinLetter = "?";
      if (cp >= 0x1d400 && cp <= 0x1d419) {
        latinLetter = String.fromCharCode(cp - 0x1d400 + 0x41);
      } else if (cp >= 0x1d41a && cp <= 0x1d433) {
        latinLetter = String.fromCharCode(cp - 0x1d41a + 0x61);
      }
      hits.push({
        codepoint: cp,
        label: labelFor(cp),
        position: i,
        latin_letter: latinLetter,
        script: "Mathematical-Alphanumeric",
      });
    }
  }

  return {
    value,
    hits,
    lookalike_scripts: Array.from(scripts),
    has_latin: hasLatin,
    has_lookalike: hasLookalike,
    is_mixed_latin_lookalike: hasLatin && hasLookalike,
    codepoint_count: cpCount,
  };
}

// ─────────────────────────── context-level gather ──────────────────────────

export function gather(context: AnalysisContext): A6Gather {
  const tools: A6ToolGather[] = [];

  for (let idx = 0; idx < context.tools.length; idx++) {
    const tool = context.tools[idx];
    const nameAnalysis = analyseField(tool.name);
    const descAnalysis = tool.description ? analyseField(tool.description) : null;
    tools.push({
      tool_name: tool.name,
      tool_index: idx,
      name_analysis: nameAnalysis,
      description_analysis: descAnalysis,
    });
  }

  // Shadow-tool detection: any two tools whose names normalise to the same
  // Latin-only string are visually identical after confusable normalisation.
  const shadowCollisions: A6Gather["shadow_collisions"] = [];
  const seenNormalised = new Map<string, A6ToolGather>();
  for (const t of tools) {
    const normalised = normaliseConfusables(t.tool_name);
    if (normalised === t.tool_name) continue; // no confusables → no collision possible
    const existing = seenNormalised.get(normalised);
    if (existing) {
      shadowCollisions.push({
        left_tool_name: existing.tool_name,
        right_tool_name: t.tool_name,
        left_tool_index: existing.tool_index,
        right_tool_index: t.tool_index,
        normalised_form: normalised,
      });
    } else {
      seenNormalised.set(normalised, t);
    }
    // Also check against tools whose name is already pure-Latin but equal to the normalised form
    for (const other of tools) {
      if (other === t) continue;
      if (other.tool_name === normalised && other.tool_name !== t.tool_name) {
        shadowCollisions.push({
          left_tool_name: other.tool_name,
          right_tool_name: t.tool_name,
          left_tool_index: other.tool_index,
          right_tool_index: t.tool_index,
          normalised_form: normalised,
        });
      }
    }
  }

  return { tools, shadow_collisions: shadowCollisions };
}
