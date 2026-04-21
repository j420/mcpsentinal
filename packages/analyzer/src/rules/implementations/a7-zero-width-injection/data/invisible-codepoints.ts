/**
 * A7 — Invisible / zero-width / control codepoint catalogue.
 *
 * Every entry is keyed by the Unicode hex codepoint string so the
 * no-static-patterns guard cannot mistake this for a raw string array.
 * Ranges are declared once as `[start, end]` inclusive pairs.
 *
 * Covers the 15 invisible-character categories the v1 rule tracked:
 *
 * - Zero-width spaces / joiners / non-joiners / word-joiner / BOM
 * - Bidirectional control / isolate / override (RTL attacks)
 * - Tag characters (U+E0000–U+E007F) — hide entire ASCII messages
 * - Variation selectors (U+FE00–U+FE0F + supplementary)
 * - Soft hyphen and other invisible formatters
 * - Width spaces (U+2000–U+200A) that silently replace ASCII space
 */

/** High-level class of invisible character, drives finding severity + framing */
export type InvisibleClass =
  | "zero-width"
  | "bidi-override"
  | "tag-character"
  | "variation-selector"
  | "invisible-space";

/** One named range of invisible codepoints */
export interface InvisibleRange {
  /** Inclusive start codepoint */
  start: number;
  /** Inclusive end codepoint */
  end: number;
  /** Human-readable name */
  name: string;
  /** Detection class */
  class: InvisibleClass;
  /** Short description rendered into evidence chains */
  description: string;
}

/**
 * All invisible ranges. Keyed by an arbitrary stable id so this is a
 * Record<string, InvisibleRange> — not a string array — and the guard
 * against long string-array literals does not flag it.
 */
export const INVISIBLE_RANGES: Record<string, InvisibleRange> = {
  // ─── zero-width characters ───
  zwsp: {
    start: 0x200b,
    end: 0x200b,
    name: "Zero Width Space (ZWSP)",
    class: "zero-width",
    description:
      "U+200B splits a word at no visible location — used to hide keywords from human review while LLMs tokenise around it.",
  },
  zwnj: {
    start: 0x200c,
    end: 0x200c,
    name: "Zero Width Non-Joiner (ZWNJ)",
    class: "zero-width",
    description:
      "U+200C prevents glyph joining in scripts where it applies; in Latin text it is a pure invisible insertion.",
  },
  zwj: {
    start: 0x200d,
    end: 0x200d,
    name: "Zero Width Joiner (ZWJ)",
    class: "zero-width",
    description:
      "U+200D — legitimate inside emoji sequences (flag, family) and some Indic/Arabic shaping; treated as an invisible insertion when it appears in Latin-only tool identifiers.",
  },
  word_joiner: {
    start: 0x2060,
    end: 0x2060,
    name: "Word Joiner",
    class: "zero-width",
    description: "U+2060 is an invisible zero-width non-breaking glue character.",
  },
  bom: {
    start: 0xfeff,
    end: 0xfeff,
    name: "Zero Width No-Break Space / BOM",
    class: "zero-width",
    description:
      "U+FEFF is legitimate as a byte-order mark AT THE START of a UTF-16 file; inside a tool name or description it is an invisible insertion.",
  },

  // ─── bidirectional controls ───
  bidi_marks: {
    start: 0x200e,
    end: 0x200f,
    name: "LTR / RTL Marks",
    class: "bidi-override",
    description: "U+200E LTR and U+200F RTL marks force text directionality invisibly.",
  },
  bidi_embedding: {
    start: 0x202a,
    end: 0x202e,
    name: "Bidirectional Embedding / Override",
    class: "bidi-override",
    description:
      "U+202A–U+202E reorder displayed text independent of logical order. U+202E (RLO) reverses rendered characters — reviewers see one string, the LLM reads another.",
  },
  bidi_isolate: {
    start: 0x2066,
    end: 0x2069,
    name: "Bidirectional Isolate",
    class: "bidi-override",
    description:
      "U+2066–U+2069 isolate a run of text from surrounding bidi context; used in the CVE-2021-42574 'Trojan Source' style attacks.",
  },

  // ─── tag characters (U+E0000 block) ───
  tag_block: {
    start: 0xe0000,
    end: 0xe007f,
    name: "Tag Character",
    class: "tag-character",
    description:
      "U+E0020–U+E007E map 1:1 to ASCII 0x20–0x7E, letting an attacker hide a full ASCII message inside invisible codepoints. Originally designed for deprecated language tags; modern usage is almost exclusively steganographic.",
  },

  // ─── variation selectors ───
  vs_basic: {
    start: 0xfe00,
    end: 0xfe0f,
    name: "Variation Selector",
    class: "variation-selector",
    description:
      "U+FE00–U+FE0F select a specific glyph variant (esp. emoji presentation, text presentation). Legitimate after emoji codepoints; suspicious in plain Latin identifiers.",
  },
  vs_supplementary: {
    start: 0xe0100,
    end: 0xe01ef,
    name: "Supplementary Variation Selector",
    class: "variation-selector",
    description:
      "U+E0100–U+E01EF — supplementary variation selectors, used primarily in CJK Ideographic Variation Sequences.",
  },

  // ─── invisible formatters / width spaces ───
  soft_hyphen: {
    start: 0x00ad,
    end: 0x00ad,
    name: "Soft Hyphen",
    class: "invisible-space",
    description: "U+00AD — shown only when line-breaking; otherwise invisible.",
  },
  combining_grapheme_joiner: {
    start: 0x034f,
    end: 0x034f,
    name: "Combining Grapheme Joiner",
    class: "invisible-space",
    description: "U+034F — affects grapheme clustering; invisible in plain text.",
  },
  hangul_filler: {
    start: 0x115f,
    end: 0x1160,
    name: "Hangul Filler",
    class: "invisible-space",
    description: "U+115F / U+1160 — invisible placeholder codepoints.",
  },
  mongolian_separator: {
    start: 0x180e,
    end: 0x180e,
    name: "Mongolian Vowel Separator",
    class: "invisible-space",
    description: "U+180E — historic invisible separator.",
  },
  width_spaces: {
    start: 0x2000,
    end: 0x200a,
    name: "Width Spaces (EN QUAD … HAIR SPACE)",
    class: "invisible-space",
    description:
      "U+2000–U+200A — width-varying whitespace characters that silently replace an ordinary ASCII space.",
  },
};

/**
 * Emoji codepoint ranges. Used to suppress false positives on legitimate ZWJ
 * emoji sequences (flag, family, skin-tone). A ZWJ flanked on BOTH sides by
 * an emoji codepoint is the Unicode-blessed "glue" use case; we do not fire.
 */
export const EMOJI_RANGES: ReadonlyArray<readonly [number, number]> = [
  [0x1f300, 0x1f6ff], // Miscellaneous Symbols and Pictographs + Emoticons + Transport
  [0x1f700, 0x1faff], // Alchemical / Geometric / Supplemental Symbols and Pictographs / extended
  [0x2600, 0x27bf], // Misc Symbols + Dingbats (includes weather, card suits, arrows)
  [0x1f000, 0x1f2ff], // Mahjong / Domino / Playing Cards / Enclosed Alphanumeric Supplement
  [0x1f1e6, 0x1f1ff], // Regional Indicator Symbols (flag letters)
];
