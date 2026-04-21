/**
 * A9 gather step — scan every description surface for encoded runs.
 *
 * Pure deterministic character-level scanning — zero regex literals. Every
 * encoded block found is emitted as an `EncodedSite` carrying:
 *   - the field the run came from (location discriminator)
 *   - the raw encoded substring + offsets (reviewers can re-extract verbatim)
 *   - the decoded payload (when the scheme decodes to printable text)
 *   - structural metrics used by the verifier (entropy, length, latin ratio)
 *
 * Categories emitted:
 *   base64-block          (≥32 base64-body chars, optional = padding, entropy ≥4.5)
 *   url-encoded-block     (≥10 %XX triplets in a run)
 *   hex-escape-block      (≥8 \xNN OR ≥6 \uNNNN in a run)
 *   html-entity-block     (≥10 & ... ; entity references in a run)
 *   mixed-encoding        (≥2 of the above categories in the same field)
 */

import {
  isBase64Body,
  isBase64Char,
  isHexDigit,
  isLatin,
  isPrintableAscii,
} from "./data/encoding-alphabets.js";
import {
  LLM_SPECIAL_TOKENS,
  findLLMSpecialToken,
} from "./data/llm-special-tokens.js";
import { countInjectionKeywords } from "./data/injection-keywords.js";
import { shannonEntropy } from "../../analyzers/entropy.js";

// ─── Thresholds (calibrated to avoid flagging natural English) ───────────────

/**
 * Minimum base64 run length. Chosen by inspecting the English-language
 * character distribution: natural English can produce ≤20-char runs of
 * base64-alphabet characters purely by chance (e.g. a URL slug), but runs
 * of 32+ chars happen only in deliberate encoding.
 */
export const MIN_BASE64_RUN = 32;

/**
 * Minimum Shannon entropy (bits/char) for a base64 candidate to count.
 *
 * Rationale: natural English text over the base64 alphabet subset tends to
 * sit around 3.8–4.3 bits/char. Real base64 of random payload sits at
 * ~5.7–6.0 bits/char. A 4.5 threshold cuts out the overlap region: we lose
 * some short/low-entropy base64 (acceptable — those are unlikely to carry
 * meaningful injection payloads) and stop false-positives from dense
 * English-alphabet runs (URL slugs, hashes presented as text).
 */
export const MIN_BASE64_ENTROPY = 4.5;

/**
 * Minimum number of %XX triplets for a URL-encoded block.
 *
 * 6 triplets = 6 decoded bytes — enough to spell short injection verbs
 * ("ignore", "system", "reveal") while still being statistically unlikely in
 * natural text. Measured English text essentially never contains 6+ contiguous
 * %XX triplets; a URL example in prose is typically a single token with a
 * handful of escapes, well below the 6-in-a-row bar.
 */
export const MIN_URL_PCT_TRIPLETS = 6;

/** Minimum number of \xNN escapes in a hex-escape block */
export const MIN_HEX_ESCAPES = 8;

/** Minimum number of \uNNNN escapes in a hex-escape block */
export const MIN_UNICODE_ESCAPES = 6;

/** Minimum number of HTML entity references in a contiguous block */
export const MIN_HTML_ENTITIES = 10;

// ─── Location discriminator (simple, typed, not a full DU) ───────────────────

export type EncodedLocation =
  | { kind: "tool-description"; tool_name: string }
  | { kind: "tool-name"; tool_name: string }
  | {
      kind: "parameter-description";
      tool_name: string;
      parameter_name: string;
    }
  | { kind: "server-instructions" }
  | { kind: "server-version" };

export function locationTag(loc: EncodedLocation): string {
  switch (loc.kind) {
    case "tool-description":
      return `tool:${loc.tool_name}:description`;
    case "tool-name":
      return `tool:${loc.tool_name}:name`;
    case "parameter-description":
      return `tool:${loc.tool_name}:param:${loc.parameter_name}:description`;
    case "server-instructions":
      return `initialize:instructions`;
    case "server-version":
      return `initialize:serverInfo.version`;
  }
}

/**
 * Convert an internal `EncodedLocation` to the v2 Rule Standard `Location`
 * discriminated union. Required for regulatory admissibility per Rule
 * Standard v2 §2 — reviewers must be able to navigate to the cited
 * position via a structured identifier, not a prose string.
 *
 * Mapping rules:
 *   tool-name / tool-description  → { kind: "tool", tool_name }
 *     (offset + field distinction captured in the link's `observed` text
 *     and in the verification step's instruction)
 *   parameter-description          → { kind: "parameter", tool_name,
 *                                     parameter_path }
 *     (parameter_path = "input_schema.properties.<name>.description")
 *   server-instructions            → { kind: "initialize", field: "instructions" }
 *   server-version                 → { kind: "initialize", field: "server_version" }
 *
 * See packages/analyzer/src/rules/location.ts for the full union.
 */
export function toStructuredLocation(
  loc: EncodedLocation,
): import("../../location.js").Location {
  switch (loc.kind) {
    case "tool-name":
    case "tool-description":
      return { kind: "tool", tool_name: loc.tool_name };
    case "parameter-description":
      return {
        kind: "parameter",
        tool_name: loc.tool_name,
        parameter_path: `input_schema.properties.${loc.parameter_name}.description`,
      };
    case "server-instructions":
      return { kind: "initialize", field: "instructions" };
    case "server-version":
      return { kind: "initialize", field: "server_version" };
  }
}

// ─── Emitted site type ───────────────────────────────────────────────────────

export type EncodedCategory =
  | "base64-block"
  | "url-encoded-block"
  | "hex-escape-block"
  | "html-entity-block";

export interface EncodedSite {
  category: EncodedCategory;
  location: EncodedLocation;
  /** Offset of the encoded run inside the source field text */
  offset: number;
  /** Length of the encoded run in characters */
  length: number;
  /** Verbatim substring of the encoded run (truncated for display if huge) */
  raw: string;
  /** Decoded payload if the scheme decoded cleanly, else null */
  decoded: string | null;
  /** Shannon entropy of the raw run (bits/char) */
  entropy: number;
  /** Ratio of Latin-script codepoints in the surrounding 200-char window */
  surrounding_latin_ratio: number;
  /** Number of injection-keyword tokens found in the decoded payload */
  keyword_hits: number;
  /** LLM-special-token string if found in decoded payload, else null */
  llm_token_hit: string | null;
}

export interface GatherResult {
  /** Every encoded site found across every surface */
  sites: EncodedSite[];
  /**
   * Set of location tags where ≥2 categories were found.
   * Populated AFTER sites are gathered so the rule can escalate them as
   * mixed-encoding findings with higher severity.
   */
  mixed_locations: Set<string>;
}

// ─── Public entry point ──────────────────────────────────────────────────────

import type { AnalysisContext } from "../../../engine.js";

export function gather(context: AnalysisContext): GatherResult {
  const sites: EncodedSite[] = [];

  for (const tool of context.tools ?? []) {
    // Tool description
    if (tool.description) {
      scanField(tool.description, { kind: "tool-description", tool_name: tool.name }, sites);
    }
    // Tool name (rare but seen — secondary surface)
    if (tool.name) {
      scanField(tool.name, { kind: "tool-name", tool_name: tool.name }, sites);
    }
    // Parameter descriptions
    const props = (tool.input_schema?.properties ?? null) as
      | Record<string, Record<string, unknown>>
      | null;
    if (props) {
      for (const [paramName, paramDef] of Object.entries(props)) {
        const desc = (paramDef?.description as string) || "";
        if (desc.length > 0) {
          scanField(
            desc,
            {
              kind: "parameter-description",
              tool_name: tool.name,
              parameter_name: paramName,
            },
            sites,
          );
        }
      }
    }
  }

  // Initialize metadata surface (H2 overlap — still A9-valid)
  const initMeta = context.initialize_metadata;
  if (initMeta?.server_instructions) {
    scanField(initMeta.server_instructions, { kind: "server-instructions" }, sites);
  }
  if (initMeta?.server_version) {
    scanField(initMeta.server_version, { kind: "server-version" }, sites);
  }

  // Compute mixed-encoding set
  const byLocation = new Map<string, Set<EncodedCategory>>();
  for (const s of sites) {
    const tag = locationTag(s.location);
    const set = byLocation.get(tag) ?? new Set();
    set.add(s.category);
    byLocation.set(tag, set);
  }
  const mixed = new Set<string>();
  for (const [tag, cats] of byLocation.entries()) {
    if (cats.size >= 2) mixed.add(tag);
  }

  return { sites, mixed_locations: mixed };
}

// ─── Per-field scanner ───────────────────────────────────────────────────────

function scanField(
  text: string,
  location: EncodedLocation,
  out: EncodedSite[],
): void {
  // Skip trivially short fields — natural-language runs can't trigger our thresholds
  if (text.length < 16) return;

  scanBase64(text, location, out);
  scanUrlEncoded(text, location, out);
  scanHexEscapes(text, location, out);
  scanUnicodeEscapes(text, location, out);
  scanHtmlEntities(text, location, out);
}

// ─── base64 scanner ──────────────────────────────────────────────────────────

function scanBase64(
  text: string,
  location: EncodedLocation,
  out: EncodedSite[],
): void {
  const n = text.length;
  let i = 0;
  while (i < n) {
    const cp = text.charCodeAt(i);
    if (!isBase64Body(cp)) {
      i++;
      continue;
    }
    // We're at the start of a candidate run. Extend while body chars continue.
    const start = i;
    while (i < n && isBase64Body(text.charCodeAt(i))) i++;
    // Optional '=' padding (at most 2) — still base64-alphabet
    let padCount = 0;
    while (i < n && padCount < 2 && text.charCodeAt(i) === 0x3d) {
      i++;
      padCount++;
    }
    const length = i - start;
    if (length < MIN_BASE64_RUN) continue;

    const raw = text.slice(start, i);
    const entropy = shannonEntropy(raw);
    if (entropy < MIN_BASE64_ENTROPY) continue;

    // Reject runs that are all-lowercase or all-uppercase *English words* —
    // those sit above 32 chars only for hash-like strings which we want to keep.
    // Our heuristic: require at least 1 digit OR at least 1 uppercase+lowercase mix.
    if (!hasBase64Variety(raw)) continue;

    const decoded = tryDecodeBase64(raw);
    const surrounding_latin_ratio = latinRatioAround(text, start, length);
    const keyword_hits = decoded ? countInjectionKeywords(decoded) : 0;
    const llm_token_hit = decoded ? findLLMSpecialToken(decoded) : null;

    out.push({
      category: "base64-block",
      location,
      offset: start,
      length,
      raw: raw.slice(0, 240),
      decoded,
      entropy,
      surrounding_latin_ratio,
      keyword_hits,
      llm_token_hit,
    });
  }
}

function hasBase64Variety(raw: string): boolean {
  let hasUpper = false;
  let hasLower = false;
  let hasDigit = false;
  for (let i = 0; i < raw.length; i++) {
    const cp = raw.charCodeAt(i);
    if (cp >= 0x41 && cp <= 0x5a) hasUpper = true;
    else if (cp >= 0x61 && cp <= 0x7a) hasLower = true;
    else if (cp >= 0x30 && cp <= 0x39) hasDigit = true;
  }
  // Genuine base64 of ≥24 bytes virtually always contains all three classes.
  return (hasUpper && hasLower) || hasDigit;
}

function tryDecodeBase64(raw: string): string | null {
  try {
    // Normalize base64url → base64 via a character-level swap (zero regex).
    let normalized = "";
    for (let i = 0; i < raw.length; i++) {
      const cp = raw.charCodeAt(i);
      if (cp === 0x2d /* - */) normalized += "+";
      else if (cp === 0x5f /* _ */) normalized += "/";
      else normalized += raw[i];
    }
    const buf = Buffer.from(normalized, "base64");
    if (buf.length === 0) return null;
    const s = buf.toString("utf-8");
    if (!looksPrintable(s)) return null;
    return s;
  } catch {
    return null;
  }
}

function looksPrintable(s: string): boolean {
  if (s.length === 0) return false;
  let printable = 0;
  for (let i = 0; i < s.length; i++) {
    if (isPrintableAscii(s.charCodeAt(i))) printable++;
  }
  return printable / s.length >= 0.8;
}

// ─── URL-encoded scanner ─────────────────────────────────────────────────────

function scanUrlEncoded(
  text: string,
  location: EncodedLocation,
  out: EncodedSite[],
): void {
  const n = text.length;
  let i = 0;
  while (i < n) {
    if (text.charCodeAt(i) !== 0x25 /* % */) {
      i++;
      continue;
    }
    // Count contiguous %XX triplets, allowing single non-triplet chars between
    let j = i;
    let triplets = 0;
    while (j + 2 < n) {
      if (
        text.charCodeAt(j) === 0x25 &&
        isHexDigit(text.charCodeAt(j + 1)) &&
        isHexDigit(text.charCodeAt(j + 2))
      ) {
        triplets++;
        j += 3;
      } else {
        break;
      }
    }
    if (triplets < MIN_URL_PCT_TRIPLETS) {
      i = i + 1;
      continue;
    }
    const raw = text.slice(i, j);
    const decoded = tryDecodeUrl(raw);
    const surrounding_latin_ratio = latinRatioAround(text, i, raw.length);
    const entropy = shannonEntropy(raw);
    const keyword_hits = decoded ? countInjectionKeywords(decoded) : 0;
    const llm_token_hit = decoded ? findLLMSpecialToken(decoded) : null;

    out.push({
      category: "url-encoded-block",
      location,
      offset: i,
      length: raw.length,
      raw: raw.slice(0, 240),
      decoded,
      entropy,
      surrounding_latin_ratio,
      keyword_hits,
      llm_token_hit,
    });
    i = j;
  }
}

function tryDecodeUrl(raw: string): string | null {
  try {
    // decodeURIComponent works only on valid triplets — which is what we scanned for.
    const decoded = decodeURIComponent(raw);
    if (!looksPrintable(decoded)) return null;
    return decoded;
  } catch {
    return null;
  }
}

// ─── \xNN scanner (JS-style hex escapes) ─────────────────────────────────────

function scanHexEscapes(
  text: string,
  location: EncodedLocation,
  out: EncodedSite[],
): void {
  const n = text.length;
  let i = 0;
  while (i < n) {
    // Look for "\x"
    if (
      i + 3 >= n ||
      text.charCodeAt(i) !== 0x5c /* \ */ ||
      text.charCodeAt(i + 1) !== 0x78 /* x */
    ) {
      i++;
      continue;
    }
    let j = i;
    let count = 0;
    while (
      j + 3 < n &&
      text.charCodeAt(j) === 0x5c &&
      text.charCodeAt(j + 1) === 0x78 &&
      isHexDigit(text.charCodeAt(j + 2)) &&
      isHexDigit(text.charCodeAt(j + 3))
    ) {
      count++;
      j += 4;
    }
    if (count < MIN_HEX_ESCAPES) {
      i = i + 1;
      continue;
    }
    const raw = text.slice(i, j);
    const decoded = tryDecodeHexEscapes(raw);
    const surrounding_latin_ratio = latinRatioAround(text, i, raw.length);
    const entropy = shannonEntropy(raw);
    const keyword_hits = decoded ? countInjectionKeywords(decoded) : 0;
    const llm_token_hit = decoded ? findLLMSpecialToken(decoded) : null;

    out.push({
      category: "hex-escape-block",
      location,
      offset: i,
      length: raw.length,
      raw: raw.slice(0, 240),
      decoded,
      entropy,
      surrounding_latin_ratio,
      keyword_hits,
      llm_token_hit,
    });
    i = j;
  }
}

function tryDecodeHexEscapes(raw: string): string | null {
  const out: number[] = [];
  for (let k = 0; k + 3 < raw.length; k += 4) {
    if (raw.charCodeAt(k) !== 0x5c || raw.charCodeAt(k + 1) !== 0x78) return null;
    const hi = hexVal(raw.charCodeAt(k + 2));
    const lo = hexVal(raw.charCodeAt(k + 3));
    if (hi < 0 || lo < 0) return null;
    out.push((hi << 4) | lo);
  }
  const s = Buffer.from(out).toString("utf-8");
  if (!looksPrintable(s)) return null;
  return s;
}

function hexVal(cp: number): number {
  if (cp >= 0x30 && cp <= 0x39) return cp - 0x30;
  if (cp >= 0x41 && cp <= 0x46) return cp - 0x41 + 10;
  if (cp >= 0x61 && cp <= 0x66) return cp - 0x61 + 10;
  return -1;
}

// ─── \uNNNN scanner ──────────────────────────────────────────────────────────

function scanUnicodeEscapes(
  text: string,
  location: EncodedLocation,
  out: EncodedSite[],
): void {
  const n = text.length;
  let i = 0;
  while (i < n) {
    if (
      i + 5 >= n ||
      text.charCodeAt(i) !== 0x5c ||
      text.charCodeAt(i + 1) !== 0x75 /* u */
    ) {
      i++;
      continue;
    }
    let j = i;
    let count = 0;
    while (
      j + 5 < n &&
      text.charCodeAt(j) === 0x5c &&
      text.charCodeAt(j + 1) === 0x75 &&
      isHexDigit(text.charCodeAt(j + 2)) &&
      isHexDigit(text.charCodeAt(j + 3)) &&
      isHexDigit(text.charCodeAt(j + 4)) &&
      isHexDigit(text.charCodeAt(j + 5))
    ) {
      count++;
      j += 6;
    }
    if (count < MIN_UNICODE_ESCAPES) {
      i = i + 1;
      continue;
    }
    const raw = text.slice(i, j);
    const decoded = tryDecodeUnicodeEscapes(raw);
    const surrounding_latin_ratio = latinRatioAround(text, i, raw.length);
    const entropy = shannonEntropy(raw);
    const keyword_hits = decoded ? countInjectionKeywords(decoded) : 0;
    const llm_token_hit = decoded ? findLLMSpecialToken(decoded) : null;

    out.push({
      category: "hex-escape-block",
      location,
      offset: i,
      length: raw.length,
      raw: raw.slice(0, 240),
      decoded,
      entropy,
      surrounding_latin_ratio,
      keyword_hits,
      llm_token_hit,
    });
    i = j;
  }
}

function tryDecodeUnicodeEscapes(raw: string): string | null {
  const chars: string[] = [];
  for (let k = 0; k + 5 < raw.length; k += 6) {
    if (raw.charCodeAt(k) !== 0x5c || raw.charCodeAt(k + 1) !== 0x75) return null;
    const h1 = hexVal(raw.charCodeAt(k + 2));
    const h2 = hexVal(raw.charCodeAt(k + 3));
    const h3 = hexVal(raw.charCodeAt(k + 4));
    const h4 = hexVal(raw.charCodeAt(k + 5));
    if (h1 < 0 || h2 < 0 || h3 < 0 || h4 < 0) return null;
    chars.push(String.fromCharCode((h1 << 12) | (h2 << 8) | (h3 << 4) | h4));
  }
  const s = chars.join("");
  // Unicode escapes may decode to non-Latin legit strings (e.g. Japanese). We
  // accept any string here — the keyword check will filter back to ASCII
  // injection patterns; non-matches just don't score the keyword factor.
  return s;
}

// ─── HTML entity scanner ─────────────────────────────────────────────────────

function scanHtmlEntities(
  text: string,
  location: EncodedLocation,
  out: EncodedSite[],
): void {
  const n = text.length;
  let i = 0;
  while (i < n) {
    if (text.charCodeAt(i) !== 0x26 /* & */) {
      i++;
      continue;
    }
    // Count consecutive & ... ; entities, allowing a single whitespace between them
    let j = i;
    let count = 0;
    while (j < n && text.charCodeAt(j) === 0x26) {
      // Find a ';' within a reasonable distance
      const semi = findSemicolon(text, j + 1, j + 10);
      if (semi < 0) break;
      count++;
      j = semi + 1;
    }
    if (count < MIN_HTML_ENTITIES) {
      i = i + 1;
      continue;
    }
    const raw = text.slice(i, j);
    const decoded = tryDecodeHtmlEntities(raw);
    const surrounding_latin_ratio = latinRatioAround(text, i, raw.length);
    const entropy = shannonEntropy(raw);
    const keyword_hits = decoded ? countInjectionKeywords(decoded) : 0;
    const llm_token_hit = decoded ? findLLMSpecialToken(decoded) : null;

    out.push({
      category: "html-entity-block",
      location,
      offset: i,
      length: raw.length,
      raw: raw.slice(0, 240),
      decoded,
      entropy,
      surrounding_latin_ratio,
      keyword_hits,
      llm_token_hit,
    });
    i = j;
  }
}

function findSemicolon(text: string, from: number, limit: number): number {
  const end = Math.min(text.length, limit);
  for (let k = from; k < end; k++) {
    if (text.charCodeAt(k) === 0x3b) return k;
  }
  return -1;
}

function tryDecodeHtmlEntities(raw: string): string | null {
  // Manual decode of numeric entities only — zero regex, zero lookup table.
  // Named entities (&amp;, &lt;) intentionally unsupported: they rarely carry
  // injection payloads (short, well-known) and the structural signal we care
  // about is the DENSITY of entity markers, not the decoded text.
  const out: string[] = [];
  let k = 0;
  while (k < raw.length) {
    if (raw.charCodeAt(k) !== 0x26) return null;
    const semi = raw.indexOf(";", k);
    if (semi < 0) return null;
    const body = raw.slice(k + 1, semi);
    if (body.length === 0) return null;
    let cp = -1;
    if (body.charCodeAt(0) === 0x23 /* # */) {
      if (body.length > 1 && (body.charCodeAt(1) === 0x78 || body.charCodeAt(1) === 0x58)) {
        // &#xNN; hex
        cp = parseInt(body.slice(2), 16);
      } else {
        // &#NN; decimal
        cp = parseInt(body.slice(1), 10);
      }
    }
    if (Number.isNaN(cp) || cp < 0 || cp > 0x10ffff) return null;
    out.push(String.fromCodePoint(cp));
    k = semi + 1;
  }
  const s = out.join("");
  if (!looksPrintable(s)) return null;
  return s;
}

// ─── Context helpers ─────────────────────────────────────────────────────────

/**
 * Measure Latin-script ratio in a ±100-char window around the block.
 * Low ratio → surrounding text is non-Latin (e.g. Japanese), so encoding
 * patterns may be legitimate literal-string examples. Used to soften
 * confidence in the verification step.
 */
function latinRatioAround(text: string, start: number, length: number): number {
  const windowStart = Math.max(0, start - 100);
  const windowEnd = Math.min(text.length, start + length + 100);
  const exclFrom = start;
  const exclTo = start + length;
  let total = 0;
  let latin = 0;
  for (let i = windowStart; i < windowEnd; i++) {
    if (i >= exclFrom && i < exclTo) continue;
    total++;
    if (isLatin(text.charCodeAt(i))) latin++;
  }
  if (total === 0) return 1;
  return latin / total;
}
