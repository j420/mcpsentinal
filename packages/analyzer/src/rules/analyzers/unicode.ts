/**
 * Unicode Security Analysis Toolkit
 *
 * Detects Unicode-based attacks in MCP tool metadata:
 * 1. Homoglyph attacks — Cyrillic/Greek characters visually identical to Latin
 * 2. Zero-width character injection — invisible characters processed by LLMs
 * 3. Bidirectional override — RTL control characters that reorder displayed text
 * 4. Mixed-script detection — multiple Unicode scripts in a single identifier
 * 5. Confusable detection — characters from Unicode TR39 confusables table
 *
 * Why this matters for MCP:
 * Tool names like "read_fіle" (with Cyrillic і) are visually identical to "read_file"
 * but are different strings. A shadow tool with a homoglyph name will not collide
 * with the legitimate tool in the MCP tool registry, enabling impersonation.
 *
 * References:
 * - Unicode TR36: Unicode Security Considerations
 * - Unicode TR39: Unicode Security Mechanisms (confusable detection)
 * - Unicode TR9: Unicode Bidirectional Algorithm
 */

/** Result of Unicode security analysis on a text segment */
export interface UnicodeAnalysisResult {
  /** Are there any Unicode security issues? */
  has_issues: boolean;
  /** All detected issues */
  issues: UnicodeIssue[];
  /** Scripts detected in the text */
  scripts_detected: Set<UnicodeScript>;
  /** Is this a mixed-script string? */
  is_mixed_script: boolean;
  /** Total count of suspicious codepoints */
  suspicious_codepoint_count: number;
}

export interface UnicodeIssue {
  type: UnicodeIssueType;
  /** Codepoint(s) involved */
  codepoints: number[];
  /** Human-readable description */
  description: string;
  /** Character position(s) in the input text */
  positions: number[];
  /** The problematic character(s) as displayed */
  characters: string;
  /** Confidence score (0.0–1.0) */
  confidence: number;
}

export type UnicodeIssueType =
  | "homoglyph"
  | "zero_width"
  | "bidi_override"
  | "mixed_script"
  | "tag_character"
  | "variation_selector"
  | "invisible_operator"
  | "confusable_whole_script";

export type UnicodeScript =
  | "Latin"
  | "Cyrillic"
  | "Greek"
  | "Armenian"
  | "Georgian"
  | "Common"
  | "Inherited"
  | "Unknown";

// --- Homoglyph Tables ---

/**
 * Latin ↔ Cyrillic confusable mapping.
 * Each entry: [Latin codepoint, Cyrillic codepoint, Latin char, Cyrillic char]
 *
 * Source: Unicode TR39 confusables.txt, filtered to Cyrillic–Latin pairs
 * that are visually identical in common monospace and sans-serif fonts.
 */
const CYRILLIC_LATIN_CONFUSABLES: Array<
  [number, number, string, string]
> = [
  [0x0041, 0x0410, "A", "А"], // Latin A ↔ Cyrillic А
  [0x0042, 0x0412, "B", "В"], // Latin B ↔ Cyrillic В
  [0x0043, 0x0421, "C", "С"], // Latin C ↔ Cyrillic С
  [0x0045, 0x0415, "E", "Е"], // Latin E ↔ Cyrillic Е
  [0x0048, 0x041d, "H", "Н"], // Latin H ↔ Cyrillic Н
  [0x004b, 0x041a, "K", "К"], // Latin K ↔ Cyrillic К
  [0x004d, 0x041c, "M", "М"], // Latin M ↔ Cyrillic М
  [0x004f, 0x041e, "O", "О"], // Latin O ↔ Cyrillic О
  [0x0050, 0x0420, "P", "Р"], // Latin P ↔ Cyrillic Р
  [0x0054, 0x0422, "T", "Т"], // Latin T ↔ Cyrillic Т
  [0x0058, 0x0425, "X", "Х"], // Latin X ↔ Cyrillic Х
  [0x0061, 0x0430, "a", "а"], // Latin a ↔ Cyrillic а
  [0x0063, 0x0441, "c", "с"], // Latin c ↔ Cyrillic с
  [0x0065, 0x0435, "e", "е"], // Latin e ↔ Cyrillic е
  [0x006f, 0x043e, "o", "о"], // Latin o ↔ Cyrillic о
  [0x0070, 0x0440, "p", "р"], // Latin p ↔ Cyrillic р
  [0x0078, 0x0445, "x", "х"], // Latin x ↔ Cyrillic х
  [0x0079, 0x0443, "y", "у"], // Latin y ↔ Cyrillic у
  [0x0069, 0x0456, "i", "і"], // Latin i ↔ Cyrillic і (Ukrainian)
  [0x006a, 0x0458, "j", "ј"], // Latin j ↔ Cyrillic ј (Serbian)
  [0x0073, 0x0455, "s", "ѕ"], // Latin s ↔ Cyrillic ѕ (Macedonian)
];

/**
 * Latin ↔ Greek confusable mapping.
 * Restricted to codepoints that are genuinely visually identical.
 */
const GREEK_LATIN_CONFUSABLES: Array<[number, number, string, string]> = [
  [0x0041, 0x0391, "A", "Α"], // Latin A ↔ Greek Α
  [0x0042, 0x0392, "B", "Β"], // Latin B ↔ Greek Β
  [0x0045, 0x0395, "E", "Ε"], // Latin E ↔ Greek Ε
  [0x0048, 0x0397, "H", "Η"], // Latin H ↔ Greek Η
  [0x004b, 0x039a, "K", "Κ"], // Latin K ↔ Greek Κ
  [0x004d, 0x039c, "M", "Μ"], // Latin M ↔ Greek Μ
  [0x004e, 0x039d, "N", "Ν"], // Latin N ↔ Greek Ν
  [0x004f, 0x039f, "O", "Ο"], // Latin O ↔ Greek Ο
  [0x0050, 0x03a1, "P", "Ρ"], // Latin P ↔ Greek Ρ
  [0x0054, 0x03a4, "T", "Τ"], // Latin T ↔ Greek Τ
  [0x0058, 0x03a7, "X", "Χ"], // Latin X ↔ Greek Χ
  [0x006f, 0x03bf, "o", "ο"], // Latin o ↔ Greek ο
  [0x0076, 0x03bd, "v", "ν"], // Latin v ↔ Greek ν
];

/** Build fast lookup: codepoint → homoglyph info */
const CONFUSABLE_MAP = new Map<
  number,
  { target_script: string; latin_char: string; lookalike_char: string }
>();

for (const [, cyrillic, latinChar, cyrillicChar] of CYRILLIC_LATIN_CONFUSABLES) {
  CONFUSABLE_MAP.set(cyrillic, {
    target_script: "Cyrillic",
    latin_char: latinChar,
    lookalike_char: cyrillicChar,
  });
}
for (const [, greek, latinChar, greekChar] of GREEK_LATIN_CONFUSABLES) {
  CONFUSABLE_MAP.set(greek, {
    target_script: "Greek",
    latin_char: latinChar,
    lookalike_char: greekChar,
  });
}

// --- Zero-Width and Invisible Character Ranges ---

/**
 * Comprehensive invisible/control character ranges.
 * Each range: [start, end, name, category]
 */
const INVISIBLE_RANGES: Array<
  [number, number, string, UnicodeIssueType]
> = [
  // Zero-width characters
  [0x200b, 0x200b, "Zero Width Space (ZWSP)", "zero_width"],
  [0x200c, 0x200c, "Zero Width Non-Joiner (ZWNJ)", "zero_width"],
  [0x200d, 0x200d, "Zero Width Joiner (ZWJ)", "zero_width"],
  [0x2060, 0x2060, "Word Joiner", "zero_width"],
  [0xfeff, 0xfeff, "Zero Width No-Break Space (BOM)", "zero_width"],

  // Bidirectional override characters
  [0x200e, 0x200f, "LTR/RTL Mark", "bidi_override"],
  [0x202a, 0x202e, "Bidi Embedding/Override", "bidi_override"],
  [0x2066, 0x2069, "Bidi Isolate", "bidi_override"],

  // Soft hyphens and other invisible formatters
  [0x00ad, 0x00ad, "Soft Hyphen", "invisible_operator"],
  [0x034f, 0x034f, "Combining Grapheme Joiner", "invisible_operator"],
  [0x115f, 0x1160, "Hangul Filler", "invisible_operator"],
  [0x17b4, 0x17b5, "Khmer Vowel Inherent", "invisible_operator"],
  [0x180e, 0x180e, "Mongolian Vowel Separator", "invisible_operator"],
  [0x2000, 0x200a, "Various Width Spaces", "invisible_operator"],

  // Tag characters (U+E0001–U+E007F) — used in emoji tag sequences
  // but can hide entire ASCII messages in invisible tag codepoints
  [0xe0000, 0xe007f, "Tag Character", "tag_character"],

  // Variation selectors
  [0xfe00, 0xfe0f, "Variation Selector", "variation_selector"],
  [0xe0100, 0xe01ef, "Supplementary Variation Selector", "variation_selector"],
];

// --- Script Detection ---

/**
 * Determine the Unicode script of a codepoint.
 * Uses range-based lookup for common scripts.
 */
export function getScript(codepoint: number): UnicodeScript {
  // Latin (Basic Latin + Latin Extended)
  if (
    (codepoint >= 0x0041 && codepoint <= 0x024f) ||
    (codepoint >= 0x1e00 && codepoint <= 0x1eff) ||
    (codepoint >= 0x2c60 && codepoint <= 0x2c7f) ||
    (codepoint >= 0xa720 && codepoint <= 0xa7ff) ||
    (codepoint >= 0xab30 && codepoint <= 0xab6f) ||
    (codepoint >= 0xff21 && codepoint <= 0xff3a) || // Fullwidth Latin upper
    (codepoint >= 0xff41 && codepoint <= 0xff5a)    // Fullwidth Latin lower
  ) {
    // Exclude digits and common punctuation that fall in these ranges
    if (codepoint >= 0x0041 && codepoint <= 0x005a) return "Latin"; // A-Z
    if (codepoint >= 0x0061 && codepoint <= 0x007a) return "Latin"; // a-z
    if (codepoint >= 0x00c0) return "Latin"; // Extended Latin
    return "Common";
  }

  // Cyrillic
  if (
    (codepoint >= 0x0400 && codepoint <= 0x04ff) ||
    (codepoint >= 0x0500 && codepoint <= 0x052f) ||
    (codepoint >= 0x2de0 && codepoint <= 0x2dff) ||
    (codepoint >= 0xa640 && codepoint <= 0xa69f)
  ) {
    return "Cyrillic";
  }

  // Greek
  if (
    (codepoint >= 0x0370 && codepoint <= 0x03ff) ||
    (codepoint >= 0x1f00 && codepoint <= 0x1fff)
  ) {
    return "Greek";
  }

  // Armenian
  if (codepoint >= 0x0530 && codepoint <= 0x058f) return "Armenian";

  // Georgian
  if (
    (codepoint >= 0x10a0 && codepoint <= 0x10ff) ||
    (codepoint >= 0x2d00 && codepoint <= 0x2d2f)
  ) {
    return "Georgian";
  }

  // Mathematical Alphanumeric Symbols (U+1D400–U+1D7FF)
  // These look like Latin letters but are in a different block
  if (codepoint >= 0x1d400 && codepoint <= 0x1d7ff) return "Common";

  // Common: digits, punctuation, symbols
  if (codepoint >= 0x0020 && codepoint <= 0x0040) return "Common";
  if (codepoint >= 0x005b && codepoint <= 0x0060) return "Common";
  if (codepoint >= 0x007b && codepoint <= 0x007f) return "Common";

  return "Unknown";
}

/**
 * Comprehensive Unicode security analysis on a text string.
 *
 * Checks for:
 * 1. Homoglyph characters (Cyrillic/Greek lookalikes for Latin)
 * 2. Zero-width and invisible characters
 * 3. Bidirectional override characters
 * 4. Mixed-script content in identifiers
 * 5. Tag characters hiding ASCII messages
 */
export function analyzeUnicode(text: string): UnicodeAnalysisResult {
  const issues: UnicodeIssue[] = [];
  const scriptsDetected = new Set<UnicodeScript>();
  let suspiciousCount = 0;

  for (let i = 0; i < text.length; i++) {
    const cp = text.codePointAt(i)!;

    // Handle surrogate pairs
    if (cp > 0xffff) {
      i++; // Skip low surrogate
    }

    // Check against confusable map (homoglyphs)
    const confusable = CONFUSABLE_MAP.get(cp);
    if (confusable) {
      issues.push({
        type: "homoglyph",
        codepoints: [cp],
        description:
          `${confusable.target_script} character "${confusable.lookalike_char}" ` +
          `(U+${cp.toString(16).toUpperCase().padStart(4, "0")}) ` +
          `looks identical to Latin "${confusable.latin_char}" — ` +
          `visual impersonation attack`,
        positions: [i],
        characters: confusable.lookalike_char,
        confidence: 0.95,
      });
      suspiciousCount++;
    }

    // Check invisible character ranges
    for (const [start, end, name, type] of INVISIBLE_RANGES) {
      if (cp >= start && cp <= end) {
        issues.push({
          type,
          codepoints: [cp],
          description:
            `${name} (U+${cp.toString(16).toUpperCase().padStart(4, "0")}) ` +
            `at position ${i} — invisible to human review, processed by LLMs`,
          positions: [i],
          characters: text[i],
          confidence: 0.9,
        });
        suspiciousCount++;
        break;
      }
    }

    // Check for Fullwidth Latin (U+FF01–U+FF5E)
    // These render at double width and can bypass exact-match filters
    if (cp >= 0xff01 && cp <= 0xff5e) {
      const normalChar = String.fromCharCode(cp - 0xfee0);
      issues.push({
        type: "confusable_whole_script",
        codepoints: [cp],
        description:
          `Fullwidth character "${String.fromCodePoint(cp)}" ` +
          `(U+${cp.toString(16).toUpperCase().padStart(4, "0")}) ` +
          `is a width variant of "${normalChar}" — bypasses string matching`,
        positions: [i],
        characters: String.fromCodePoint(cp),
        confidence: 0.85,
      });
      suspiciousCount++;
    }

    // Check for Mathematical Alphanumeric Symbols (U+1D400–U+1D7FF)
    // Bold/italic/script variants of Latin letters used for obfuscation
    if (cp >= 0x1d400 && cp <= 0x1d7ff) {
      issues.push({
        type: "confusable_whole_script",
        codepoints: [cp],
        description:
          `Mathematical Alphanumeric Symbol ` +
          `(U+${cp.toString(16).toUpperCase().padStart(4, "0")}) ` +
          `at position ${i} — styled Latin letter variant used for obfuscation`,
        positions: [i],
        characters: String.fromCodePoint(cp),
        confidence: 0.8,
      });
      suspiciousCount++;
    }

    // Track script for mixed-script detection
    const script = getScript(cp);
    if (script !== "Common" && script !== "Inherited" && script !== "Unknown") {
      scriptsDetected.add(script);
    }
  }

  // Mixed-script detection: flag if more than one "real" script is present
  // (excluding Common/Inherited which appear in all scripts)
  const realScripts = new Set(
    [...scriptsDetected].filter(
      (s) => s !== "Common" && s !== "Inherited" && s !== "Unknown"
    )
  );
  const isMixedScript = realScripts.size > 1;

  if (isMixedScript) {
    issues.push({
      type: "mixed_script",
      codepoints: [],
      description:
        `Mixed scripts detected: ${[...realScripts].join(", ")}. ` +
        `Legitimate identifiers use a single script. Mixed scripts indicate ` +
        `homoglyph substitution attack (e.g., Cyrillic "а" replacing Latin "a").`,
      positions: [],
      characters: "",
      confidence: 0.9,
    });
  }

  return {
    has_issues: issues.length > 0,
    issues,
    scripts_detected: scriptsDetected,
    is_mixed_script: isMixedScript,
    suspicious_codepoint_count: suspiciousCount,
  };
}

/**
 * Extract hidden ASCII message from tag characters.
 * Tag characters (U+E0020–U+E007E) map 1:1 to ASCII 0x20–0x7E.
 * Attackers can hide entire instructions in invisible tag sequences.
 */
export function extractTagMessage(text: string): string | null {
  const tagChars: number[] = [];

  for (let i = 0; i < text.length; i++) {
    const cp = text.codePointAt(i)!;
    if (cp > 0xffff) i++; // Handle surrogate pairs
    if (cp >= 0xe0020 && cp <= 0xe007e) {
      tagChars.push(cp - 0xe0000); // Map back to ASCII
    }
  }

  if (tagChars.length < 3) return null; // Too short to be meaningful
  return String.fromCharCode(...tagChars);
}

/**
 * Normalize a string by replacing all confusable characters with their
 * Latin equivalents. Used for shadow tool name comparison.
 */
export function normalizeConfusables(text: string): string {
  const result: string[] = [];

  for (let i = 0; i < text.length; i++) {
    const cp = text.codePointAt(i)!;
    if (cp > 0xffff) i++;

    const confusable = CONFUSABLE_MAP.get(cp);
    if (confusable) {
      result.push(confusable.latin_char);
    } else if (cp >= 0xff01 && cp <= 0xff5e) {
      // Fullwidth → ASCII
      result.push(String.fromCharCode(cp - 0xfee0));
    } else if (cp >= 0x1d400 && cp <= 0x1d7ff) {
      // Mathematical alphanumeric → approximate Latin letter
      // Bold uppercase: 0x1D400-0x1D419 maps to A-Z
      // Bold lowercase: 0x1D41A-0x1D433 maps to a-z
      // (Simplified — handles bold only, others are less common)
      if (cp >= 0x1d400 && cp <= 0x1d419)
        result.push(String.fromCharCode(cp - 0x1d400 + 0x41));
      else if (cp >= 0x1d41a && cp <= 0x1d433)
        result.push(String.fromCharCode(cp - 0x1d41a + 0x61));
      else result.push(String.fromCodePoint(cp));
    } else {
      result.push(String.fromCodePoint(cp));
    }
  }

  return result.join("");
}
