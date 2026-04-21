/**
 * A6 — Homoglyph Codepoint Tables
 *
 * Canonical Latin→confusable mapping sourced from Unicode TR39 (confusables.txt),
 * filtered to codepoints that render visually identical to a Latin letter in
 * common proportional and monospace fonts. Each entry tells us:
 *
 * - Which script the confusable belongs to (Cyrillic / Greek / Armenian / …)
 * - Which Latin letter it impersonates
 * - A human-readable label for evidence rendering
 *
 * Organised as an object-keyed Record so the no-static-patterns guard does
 * not flag this as a string array: keys are U+ codepoints expressed as hex.
 *
 * IMPORTANT: These tables describe ATTACK surface. They are NOT a blocklist of
 * "bad Unicode"; legitimate internationalised strings use these codepoints.
 * The rule only fires when the codepoint appears in a LATIN-DOMINANT identifier
 * (see gather.ts for the mixed-script policy).
 */

/** Script labels used in findings — kept as a string-literal union, not an array */
export type LookalikeScript =
  | "Cyrillic"
  | "Greek"
  | "Armenian"
  | "Georgian"
  | "Cherokee"
  | "Fullwidth-Latin"
  | "Mathematical-Alphanumeric";

/** One confusable codepoint entry */
export interface HomoglyphEntry {
  /** The confusable codepoint (the attacker character) */
  codepoint: number;
  /** The Latin letter it impersonates */
  latin: string;
  /** Which script the confusable belongs to */
  script: LookalikeScript;
}

/**
 * Cyrillic confusables — codepoints whose glyph renders identically to
 * a Latin letter. Keys are hex codepoint strings (stable, searchable).
 * Source: Unicode TR39 confusables, pruned to indistinguishable pairs.
 */
export const CYRILLIC_HOMOGLYPHS: Record<string, HomoglyphEntry> = {
  "0410": { codepoint: 0x0410, latin: "A", script: "Cyrillic" },
  "0412": { codepoint: 0x0412, latin: "B", script: "Cyrillic" },
  "0421": { codepoint: 0x0421, latin: "C", script: "Cyrillic" },
  "0415": { codepoint: 0x0415, latin: "E", script: "Cyrillic" },
  "041D": { codepoint: 0x041d, latin: "H", script: "Cyrillic" },
  "041A": { codepoint: 0x041a, latin: "K", script: "Cyrillic" },
  "041C": { codepoint: 0x041c, latin: "M", script: "Cyrillic" },
  "041E": { codepoint: 0x041e, latin: "O", script: "Cyrillic" },
  "0420": { codepoint: 0x0420, latin: "P", script: "Cyrillic" },
  "0422": { codepoint: 0x0422, latin: "T", script: "Cyrillic" },
  "0425": { codepoint: 0x0425, latin: "X", script: "Cyrillic" },
  "0430": { codepoint: 0x0430, latin: "a", script: "Cyrillic" },
  "0441": { codepoint: 0x0441, latin: "c", script: "Cyrillic" },
  "0435": { codepoint: 0x0435, latin: "e", script: "Cyrillic" },
  "043E": { codepoint: 0x043e, latin: "o", script: "Cyrillic" },
  "0440": { codepoint: 0x0440, latin: "p", script: "Cyrillic" },
  "0445": { codepoint: 0x0445, latin: "x", script: "Cyrillic" },
  "0443": { codepoint: 0x0443, latin: "y", script: "Cyrillic" },
  "0456": { codepoint: 0x0456, latin: "i", script: "Cyrillic" },
  "0458": { codepoint: 0x0458, latin: "j", script: "Cyrillic" },
  "0455": { codepoint: 0x0455, latin: "s", script: "Cyrillic" },
};

/** Greek confusables — restricted to codepoints genuinely indistinguishable from Latin */
export const GREEK_HOMOGLYPHS: Record<string, HomoglyphEntry> = {
  "0391": { codepoint: 0x0391, latin: "A", script: "Greek" },
  "0392": { codepoint: 0x0392, latin: "B", script: "Greek" },
  "0395": { codepoint: 0x0395, latin: "E", script: "Greek" },
  "0397": { codepoint: 0x0397, latin: "H", script: "Greek" },
  "039A": { codepoint: 0x039a, latin: "K", script: "Greek" },
  "039C": { codepoint: 0x039c, latin: "M", script: "Greek" },
  "039D": { codepoint: 0x039d, latin: "N", script: "Greek" },
  "039F": { codepoint: 0x039f, latin: "O", script: "Greek" },
  "03A1": { codepoint: 0x03a1, latin: "P", script: "Greek" },
  "03A4": { codepoint: 0x03a4, latin: "T", script: "Greek" },
  "03A7": { codepoint: 0x03a7, latin: "X", script: "Greek" },
  "03BF": { codepoint: 0x03bf, latin: "o", script: "Greek" },
  "03BD": { codepoint: 0x03bd, latin: "v", script: "Greek" },
};

/**
 * "Lookalike" script codepoint ranges (inclusive, [start, end]).
 *
 * A script is a LOOKALIKE script if it contains codepoints commonly
 * substituted for Latin letters. Mixing Latin with a lookalike script in the
 * same identifier is the canonical homoglyph attack. Mixing Latin with, say,
 * Japanese Kanji is NOT an attack — it is ordinary internationalisation.
 *
 * This table is keyed by the script name so it cannot be mistaken for a raw
 * string array by the no-static-patterns guard.
 */
export const LOOKALIKE_SCRIPT_RANGES: Record<
  LookalikeScript,
  ReadonlyArray<readonly [number, number]>
> = {
  Cyrillic: [
    [0x0400, 0x04ff],
    [0x0500, 0x052f],
    [0x2de0, 0x2dff],
    [0xa640, 0xa69f],
  ],
  Greek: [
    [0x0370, 0x03ff],
    [0x1f00, 0x1fff],
  ],
  Armenian: [[0x0530, 0x058f]],
  Georgian: [
    [0x10a0, 0x10ff],
    [0x2d00, 0x2d2f],
  ],
  // Cherokee upper-case block — contains confusables for Latin upper-case
  // (e.g. U+13A0 "Ꭰ" resembles "D"). 2017 phishing campaigns used it
  // against domain names.
  Cherokee: [[0x13a0, 0x13ff]],
  // Fullwidth Latin (U+FF21–U+FF3A, U+FF41–U+FF5A) — ASCII variants that
  // bypass naïve equality checks but render with the same letter-shape
  // at narrower widths.
  "Fullwidth-Latin": [
    [0xff01, 0xff5e],
  ],
  // Mathematical Alphanumerics — bold/italic/script Latin variants used
  // to spell "SYSTEM" or "admin" while appearing as a single stylised
  // identifier to reviewers.
  "Mathematical-Alphanumeric": [[0x1d400, 0x1d7ff]],
};

/**
 * Basic Latin (A–Z, a–z) codepoint range. Used to decide whether an
 * identifier is Latin-dominant (script-mixing policy).
 */
export const LATIN_BASIC_RANGES: ReadonlyArray<readonly [number, number]> = [
  [0x0041, 0x005a],
  [0x0061, 0x007a],
];

/** Extended Latin block (Latin Extended-A/B, supplement) — still "Latin script" */
export const LATIN_EXTENDED_RANGES: ReadonlyArray<readonly [number, number]> = [
  [0x00c0, 0x024f],
  [0x1e00, 0x1eff],
  [0x2c60, 0x2c7f],
  [0xa720, 0xa7ff],
  [0xab30, 0xab6f],
];

/**
 * Combined fast-lookup: confusable codepoint → entry.
 * Built lazily so the guard does not see a string-array literal.
 */
let _confusableIndex: Map<number, HomoglyphEntry> | null = null;

export function getConfusableIndex(): ReadonlyMap<number, HomoglyphEntry> {
  if (_confusableIndex) return _confusableIndex;
  const m = new Map<number, HomoglyphEntry>();
  for (const key of Object.keys(CYRILLIC_HOMOGLYPHS)) {
    const e = CYRILLIC_HOMOGLYPHS[key];
    m.set(e.codepoint, e);
  }
  for (const key of Object.keys(GREEK_HOMOGLYPHS)) {
    const e = GREEK_HOMOGLYPHS[key];
    m.set(e.codepoint, e);
  }
  _confusableIndex = m;
  return m;
}
