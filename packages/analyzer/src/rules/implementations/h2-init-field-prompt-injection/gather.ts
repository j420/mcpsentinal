/**
 * H2 gather step — per-field fact collection over the three MCP
 * initialize handshake fields.
 *
 * Surfaces scanned:
 *   - context.server.name                                  (server_name)
 *   - context.initialize_metadata.server_version           (server_version)
 *   - context.initialize_metadata.server_instructions      (instructions)
 *
 * Silent skip: when `context.initialize_metadata` is undefined/null the
 * gatherer still scans `server.name` (always present on the context)
 * but produces zero hits for the other two fields. The orchestrator
 * short-circuits when no hits exist across any field.
 *
 * NO regex literals. All scanning is character-level tokenisation,
 * exact-substring lookup, delegated Unicode analysis, or entropy-gated
 * base64 detection — mirrors the deterministic style established by A1,
 * A7 and A9 in earlier waves.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import { analyzeUnicode } from "../../analyzers/unicode.js";
import { shannonEntropy } from "../../analyzers/entropy.js";
import {
  findSpecialTokens,
  type SpecialTokenHit,
} from "./data/llm-special-tokens.js";
import {
  INSTRUCTION_PHRASES,
  type InstructionPhraseSpec,
  type InstructionCategory,
} from "./data/instruction-phrases.js";

// ─── Typed field identifiers ────────────────────────────────────────────────

export type InitField = "server_name" | "server_version" | "instructions";

/** Convert an internal field id → a structured v2 Location. */
export function fieldLocation(field: InitField): Location {
  return { kind: "initialize", field };
}

// ─── Site types — one entry per finding-worthy observation ──────────────────

export type SiteKind =
  | "phrase-match"
  | "special-token"
  | "unicode-control"
  | "base64-payload"
  | "version-shape";

export interface FieldSite {
  field: InitField;
  /** What produced the signal. */
  kind: SiteKind;
  /** Char offset where the signal begins inside the field. */
  offset: number;
  /** Length of the matched substring (chars). */
  length: number;
  /** Verbatim substring (truncated at 160 chars for display). */
  observed: string;
  /** Independent probability weight for noisy-OR aggregation. */
  weight: number;
  /** Human-readable label for evidence narrative. */
  label: string;
  /** Optional category label — only populated for phrase matches. */
  category: InstructionCategory | null;
  /** Optional: for base64 payload sites, the decoded string. */
  decoded?: string;
}

export interface H2Gathered {
  /** Map: field id → sites in that field. */
  byField: Map<InitField, FieldSite[]>;
  /** All sites across every field, in traversal order. */
  all: FieldSite[];
}

// ─── Character-level tokeniser (shared pattern with A1 / G5) ────────────────

interface Token {
  text: string;
  offset: number;
}

function isWordChar(cp: number): boolean {
  return (
    (cp >= 0x30 && cp <= 0x39) ||
    (cp >= 0x41 && cp <= 0x5a) ||
    (cp >= 0x61 && cp <= 0x7a) ||
    cp === 0x5f
  );
}

function lowerAscii(cp: number): string {
  if (cp >= 0x41 && cp <= 0x5a) return String.fromCharCode(cp + 32);
  return String.fromCharCode(cp);
}

function tokenise(text: string): Token[] {
  const out: Token[] = [];
  const n = text.length;
  let i = 0;
  while (i < n) {
    const cp = text.charCodeAt(i);
    if (isWordChar(cp)) {
      const start = i;
      let buf = "";
      while (i < n && isWordChar(text.charCodeAt(i))) {
        buf += lowerAscii(text.charCodeAt(i));
        i++;
      }
      out.push({ text: buf, offset: start });
    } else {
      i++;
    }
  }
  return out;
}

// ─── Phrase matcher (tokens in order with max gap) ──────────────────────────

function findPhrase(
  tokens: Token[],
  spec: InstructionPhraseSpec,
): Array<{ start_tok: number; end_tok: number }> {
  const hits: Array<{ start_tok: number; end_tok: number }> = [];
  const n = tokens.length;
  const k = spec.tokens.length;
  if (k === 0) return hits;

  for (let i = 0; i < n; i++) {
    if (tokens[i].text !== spec.tokens[0]) continue;
    let matchedIdx = i;
    let ok = true;
    for (let t = 1; t < k; t++) {
      let j = matchedIdx + 1;
      const limit = Math.min(n, j + spec.max_gap + 1);
      let found = -1;
      while (j < limit) {
        if (tokens[j].text === spec.tokens[t]) {
          found = j;
          break;
        }
        j++;
      }
      if (found < 0) {
        ok = false;
        break;
      }
      matchedIdx = found;
    }
    if (ok) hits.push({ start_tok: i, end_tok: matchedIdx });
  }
  return hits;
}

// ─── Base64 scanner (structural — same thresholds as A9) ────────────────────

/** Minimum base64 run length before we flag it (below this is plausibly a hash). */
const MIN_BASE64_RUN = 32;
/** Minimum Shannon entropy (bits/char) for a base64 candidate. */
const MIN_BASE64_ENTROPY = 4.5;

function isBase64Body(cp: number): boolean {
  return (
    (cp >= 0x41 && cp <= 0x5a) || // A-Z
    (cp >= 0x61 && cp <= 0x7a) || // a-z
    (cp >= 0x30 && cp <= 0x39) || // 0-9
    cp === 0x2b || // +
    cp === 0x2f || // /
    cp === 0x2d || // - (url-safe)
    cp === 0x5f // _ (url-safe)
  );
}

interface Base64Hit {
  offset: number;
  length: number;
  raw: string;
  entropy: number;
  decoded: string | null;
}

function scanBase64(text: string): Base64Hit[] {
  const hits: Base64Hit[] = [];
  const n = text.length;
  let i = 0;
  while (i < n) {
    if (!isBase64Body(text.charCodeAt(i))) {
      i++;
      continue;
    }
    const start = i;
    while (i < n && isBase64Body(text.charCodeAt(i))) i++;
    // Optional '=' padding
    let pad = 0;
    while (i < n && pad < 2 && text.charCodeAt(i) === 0x3d) {
      i++;
      pad++;
    }
    const length = i - start;
    if (length < MIN_BASE64_RUN) continue;
    const raw = text.slice(start, i);
    const entropy = shannonEntropy(raw);
    if (entropy < MIN_BASE64_ENTROPY) continue;
    if (!hasBase64Variety(raw)) continue;
    const decoded = tryDecodeBase64(raw);
    hits.push({ offset: start, length, raw, entropy, decoded });
  }
  return hits;
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
  return (hasUpper && hasLower) || hasDigit;
}

function tryDecodeBase64(raw: string): string | null {
  try {
    let normalized = "";
    for (let i = 0; i < raw.length; i++) {
      const cp = raw.charCodeAt(i);
      if (cp === 0x2d) normalized += "+";
      else if (cp === 0x5f) normalized += "/";
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
    const cp = s.charCodeAt(i);
    if ((cp >= 0x20 && cp <= 0x7e) || cp === 0x09 || cp === 0x0a || cp === 0x0d) {
      printable++;
    }
  }
  return printable / s.length >= 0.8;
}

// ─── Semver shape check ─────────────────────────────────────────────────────

/**
 * Returns true when `v` looks like a plausible semver:
 *   major.minor.patch[-prerelease][+build]
 *   all-ASCII, length ≤32, no whitespace/control chars.
 * NO regex — the structural check is done manually.
 */
function looksLikeSemver(v: string): boolean {
  if (v.length === 0 || v.length > 32) return false;
  // Count dots in the leading MAJOR.MINOR.PATCH triad
  let dotCount = 0;
  let i = 0;
  let sawDigit = false;
  while (i < v.length) {
    const cp = v.charCodeAt(i);
    if (cp >= 0x30 && cp <= 0x39) {
      sawDigit = true;
      i++;
    } else if (cp === 0x2e /* . */) {
      if (!sawDigit) return false;
      sawDigit = false;
      dotCount++;
      if (dotCount > 2) return false;
      i++;
    } else if (cp === 0x2d /* - */ || cp === 0x2b /* + */) {
      break;
    } else {
      return false;
    }
  }
  if (dotCount !== 2 || !sawDigit) return false;
  // Remainder (prerelease / build) must be ASCII alphanumerics + .-+_
  for (let j = i; j < v.length; j++) {
    const cp = v.charCodeAt(j);
    const ok =
      (cp >= 0x30 && cp <= 0x39) ||
      (cp >= 0x41 && cp <= 0x5a) ||
      (cp >= 0x61 && cp <= 0x7a) ||
      cp === 0x2e ||
      cp === 0x2d ||
      cp === 0x2b ||
      cp === 0x5f;
    if (!ok) return false;
  }
  return true;
}

// ─── Per-field scanner ──────────────────────────────────────────────────────

function scanField(field: InitField, text: string, out: FieldSite[]): void {
  if (text.length === 0) return;

  // 1. LLM special-token exact-substring hits (all fields).
  const specials = findSpecialTokens(text);
  for (const hit of specials) {
    out.push({
      field,
      kind: "special-token",
      offset: hit.offset,
      length: hit.token.length,
      observed: hit.token,
      weight: hit.spec.weight,
      label: hit.spec.label,
      category: null,
    });
  }

  // 2. Unicode control characters (all fields) — delegated codepoint analysis.
  const uni = analyzeUnicode(text);
  for (const issue of uni.issues) {
    if (
      issue.type === "zero_width" ||
      issue.type === "bidi_override" ||
      issue.type === "tag_character" ||
      issue.type === "variation_selector" ||
      issue.type === "invisible_operator"
    ) {
      const pos = issue.positions[0] ?? 0;
      out.push({
        field,
        kind: "unicode-control",
        offset: pos,
        length: 1,
        observed: `U+${issue.codepoints[0]?.toString(16).toUpperCase().padStart(4, "0") ?? "????"}`,
        weight: Math.max(0.85, issue.confidence),
        label: `Unicode control (${issue.type})`,
        category: null,
      });
    }
  }

  // 3. Phrase catalogue match — ONLY on instructions (name/version are
  //    short identifiers; phrase matching there would produce noise).
  if (field === "instructions") {
    const tokens = tokenise(text);
    for (const spec of INSTRUCTION_PHRASES) {
      const hits = findPhrase(tokens, spec);
      for (const span of hits) {
        const startChar = tokens[span.start_tok].offset;
        const endTok = tokens[span.end_tok];
        const endChar = endTok.offset + endTok.text.length;
        const observed = text.slice(startChar, endChar).slice(0, 160);
        out.push({
          field,
          kind: "phrase-match",
          offset: startChar,
          length: endChar - startChar,
          observed,
          weight: spec.weight,
          label: spec.label,
          category: spec.category,
        });
      }
    }

    // 4. Base64 hidden-payload scan (instructions only — the natural
    //    surface for a hidden long run). A name or version long enough
    //    to hide a 32-char base64 payload is already an anomaly caught
    //    by the version-shape check.
    const base64Hits = scanBase64(text);
    for (const b of base64Hits) {
      out.push({
        field,
        kind: "base64-payload",
        offset: b.offset,
        length: b.length,
        observed: b.raw.slice(0, 160),
        // Stronger confidence when the decoded payload contains an
        // LLM special token — otherwise the base64 presence alone is
        // medium confidence.
        weight: b.decoded && findSpecialTokens(b.decoded).length > 0 ? 0.92 : 0.78,
        label: b.decoded
          ? `base64 payload (decoded length ${b.decoded.length})`
          : "base64 payload (undecodable)",
        category: null,
        decoded: b.decoded ?? undefined,
      });
    }
  }

  // 5. serverInfo.version shape check — oversize non-semver is the injection
  //    signal (a normal semver is <32 chars; anything much longer is carrying
  //    content that doesn't belong in a version field). Short non-semver
  //    strings like "2.0", "v3", "beta" are legitimate real-world version
  //    formats and must NOT fire — spec-compliance is F4 territory, not H2.
  if (field === "server_version") {
    if (!looksLikeSemver(text) && text.length > 32) {
      out.push({
        field,
        kind: "version-shape",
        offset: 0,
        length: Math.min(text.length, 160),
        observed: text.slice(0, 160),
        weight: 0.82,
        label: "version shape — non-semver + oversize",
        category: null,
      });
    }
  }
}

// ─── Public entry point ─────────────────────────────────────────────────────

export function gatherH2(context: AnalysisContext): H2Gathered {
  const byField = new Map<InitField, FieldSite[]>();
  const all: FieldSite[] = [];

  const meta = context.initialize_metadata;

  // server.name is always present on context (required by schema).
  const serverName = context.server?.name ?? "";
  if (serverName.length > 0) {
    const sites: FieldSite[] = [];
    scanField("server_name", serverName, sites);
    if (sites.length > 0) byField.set("server_name", sites);
    all.push(...sites);
  }

  // server_version + instructions only when live initialize metadata exists.
  if (meta?.server_version) {
    const sites: FieldSite[] = [];
    scanField("server_version", meta.server_version, sites);
    if (sites.length > 0) byField.set("server_version", sites);
    all.push(...sites);
  }
  if (meta?.server_instructions) {
    const sites: FieldSite[] = [];
    scanField("instructions", meta.server_instructions, sites);
    if (sites.length > 0) byField.set("instructions", sites);
    all.push(...sites);
  }

  return { byField, all };
}
