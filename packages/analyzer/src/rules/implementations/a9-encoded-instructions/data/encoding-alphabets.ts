/**
 * Character alphabets for encoded-content scanning (A9).
 *
 * Stored as `Record<char, true>` lookups so the gather step can run a
 * character-level scanner without regex literals or long string-array
 * constants (enforces the "no-static-patterns" contract).
 *
 * Coverage contract (be honest about limits):
 *   - Standard base64 (RFC 4648) + base64url (- and _ variants)
 *   - Hex (lower + upper)
 *   - URL-encoded percent triplets (%XX)
 *   - JavaScript / JSON-style escapes (\xXX, \uXXXX)
 *   - HTML entity start/end markers
 *
 * NOT covered (acknowledged gaps):
 *   - base32 (RFC 4648 §6) — requires its own alphabet
 *   - ascii85 / base85 — printable-range sensitive, future work
 *   - XOR-obfuscated payloads — covered by entropy analysis, not this module
 *   - Unicode homoglyph obfuscation — handled by A6/A7 rules
 */

/** Standard base64 + base64url alphabet (A-Z a-z 0-9 + / - _) plus padding '=' */
export const BASE64_ALPHABET: Record<string, true> = (() => {
  const r: Record<string, true> = {};
  // A-Z
  for (let c = 65; c <= 90; c++) r[String.fromCharCode(c)] = true;
  // a-z
  for (let c = 97; c <= 122; c++) r[String.fromCharCode(c)] = true;
  // 0-9
  for (let c = 48; c <= 57; c++) r[String.fromCharCode(c)] = true;
  // standard base64 + base64url
  r["+"] = true;
  r["/"] = true;
  r["-"] = true;
  r["_"] = true;
  // padding
  r["="] = true;
  return r;
})();

/** Characters that are legal inside a continuous base64 run (no padding) */
export const BASE64_BODY: Record<string, true> = (() => {
  const r: Record<string, true> = { ...BASE64_ALPHABET };
  delete r["="];
  return r;
})();

/** Hex digits (case-insensitive) */
export const HEX_DIGITS: Record<string, true> = (() => {
  const r: Record<string, true> = {};
  for (let c = 48; c <= 57; c++) r[String.fromCharCode(c)] = true; // 0-9
  for (let c = 65; c <= 70; c++) r[String.fromCharCode(c)] = true; // A-F
  for (let c = 97; c <= 102; c++) r[String.fromCharCode(c)] = true; // a-f
  return r;
})();

/** ASCII printable range (used to judge decoded-payload readability) */
export const PRINTABLE_ASCII: Record<number, true> = (() => {
  const r: Record<number, true> = {};
  for (let c = 0x20; c <= 0x7e; c++) r[c] = true;
  r[0x09] = true; // tab
  r[0x0a] = true; // LF
  r[0x0d] = true; // CR
  return r;
})();

/** Character indicating start of an HTML entity */
export const HTML_ENTITY_START = "&" as const;
/** Character indicating end of an HTML entity */
export const HTML_ENTITY_END = ";" as const;
/** Character beginning a JavaScript/JSON hex escape (\xNN) */
export const JS_HEX_ESCAPE_PREFIX = "x" as const;
/** Character beginning a JavaScript/JSON unicode escape (\uNNNN) */
export const JS_UNI_ESCAPE_PREFIX = "u" as const;
/** Character beginning a URL-encoded triplet */
export const URL_PCT = "%" as const;

/**
 * True if a codepoint is a base64 alphabet character.
 * Separate from BASE64_ALPHABET so callers can scan via charCodeAt without
 * allocating a string per character.
 */
export function isBase64Char(cp: number): boolean {
  return (
    (cp >= 0x41 && cp <= 0x5a) || // A-Z
    (cp >= 0x61 && cp <= 0x7a) || // a-z
    (cp >= 0x30 && cp <= 0x39) || // 0-9
    cp === 0x2b || // +
    cp === 0x2f || // /
    cp === 0x2d || // - (base64url)
    cp === 0x5f || // _ (base64url)
    cp === 0x3d // = (padding — only valid at tail)
  );
}

/** True if a codepoint can appear in the body of a base64 run (no padding) */
export function isBase64Body(cp: number): boolean {
  return (
    (cp >= 0x41 && cp <= 0x5a) ||
    (cp >= 0x61 && cp <= 0x7a) ||
    (cp >= 0x30 && cp <= 0x39) ||
    cp === 0x2b ||
    cp === 0x2f ||
    cp === 0x2d ||
    cp === 0x5f
  );
}

/** True if a codepoint is a hex digit (case-insensitive) */
export function isHexDigit(cp: number): boolean {
  return (
    (cp >= 0x30 && cp <= 0x39) ||
    (cp >= 0x41 && cp <= 0x46) ||
    (cp >= 0x61 && cp <= 0x66)
  );
}

/** True if a codepoint is ASCII-printable (includes basic whitespace) */
export function isPrintableAscii(cp: number): boolean {
  return (cp >= 0x20 && cp <= 0x7e) || cp === 0x09 || cp === 0x0a || cp === 0x0d;
}

/** True if the codepoint is in the Latin script (proxy for "English-adjacent text") */
export function isLatin(cp: number): boolean {
  return (
    (cp >= 0x20 && cp <= 0x7e) || // basic Latin + ASCII punctuation
    (cp >= 0xa0 && cp <= 0xff) || // Latin-1 supplement
    (cp >= 0x100 && cp <= 0x24f) // Latin Extended A/B
  );
}
