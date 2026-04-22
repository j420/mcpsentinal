/**
 * L3 evidence gathering — deterministic tokenisation of Dockerfile FROM
 * instructions. No regex literals. Every list lives in ./data/ as a typed
 * Record or small allowlist.
 *
 * The input can arrive in either:
 *   - context.source_files (Map<path, text>): we scan every file whose basename
 *     begins with "Dockerfile" (case-insensitive) — includes "Dockerfile",
 *     "Dockerfile.prod", "Dockerfile.mcp" — so attackers can't hide a
 *     base-image in `Dockerfile.staging`.
 *   - context.source_code (concatenated): we treat the whole blob as a single
 *     Dockerfile candidate. Degraded but still produces findings.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  MUTABLE_TAG_KEYWORDS,
  SCRATCH_IMAGE_LITERAL,
  FROM_FLAG_PREFIXES,
} from "./data/mutable-tags.js";

// ─── Public types ──────────────────────────────────────────────────────────

/** A single FROM instruction parsed out of a Dockerfile. */
export interface FromInstruction {
  /** File the Dockerfile lives in. "<concatenated-source>" when no source_files. */
  file: string;
  /** 1-based line number. */
  line: number;
  /** The raw line text, trimmed and length-capped. */
  raw: string;
  /** Image reference ("alpine", "node", "scratch", "$BASE"). */
  image: string;
  /** Tag if present ("3.18", "latest", null if missing). */
  tag: string | null;
  /** SHA256 digest if present (already includes "sha256:" prefix). */
  digest: string | null;
  /** Stage alias from `AS <name>` clause. */
  stage: string | null;
  /** True when the image reference contains an unresolved ARG ($VAR / ${VAR}). */
  usesArgReference: boolean;
}

/** Problem classification for a FROM. `null` means no problem found. */
export type FromProblem =
  | { kind: "no-tag"; detail: string }
  | { kind: "mutable-tag"; matchedKeyword: string; detail: string }
  | { kind: "arg-reference"; detail: string }
  | null;

/** An L3 finding candidate — one per problematic FROM. */
export interface L3Fact {
  from: FromInstruction;
  problem: Exclude<FromProblem, null>;
  /** Structured source-kind Location pointing at the FROM line. */
  location: Location;
  /** Structured config-kind Location pointing at the FROM instruction within the Dockerfile. */
  configLocation: Location;
  /** Across the same Dockerfile: is ANY FROM digest-pinned? */
  hasAnyDigestInFile: boolean;
  /** Across the same Dockerfile: total stage count. */
  totalStagesInFile: number;
  /** Across the same Dockerfile: how many stages ARE digest-pinned. */
  pinnedStagesInFile: number;
}

export interface L3GatherResult {
  facts: L3Fact[];
  /** File paths we scanned. Useful in tests. */
  scannedFiles: string[];
}

// ─── Entry point ───────────────────────────────────────────────────────────

export function gatherL3(context: AnalysisContext): L3GatherResult {
  const candidateFiles = collectCandidateFiles(context);
  const facts: L3Fact[] = [];
  const scannedFiles: string[] = [];

  for (const [file, text] of candidateFiles) {
    scannedFiles.push(file);
    const froms = parseDockerfileFroms(file, text);
    if (froms.length === 0) continue;

    const hasAnyDigest = froms.some((f) => f.digest !== null);
    const pinnedCount = froms.filter((f) => f.digest !== null).length;

    for (const from of froms) {
      const problem = classifyFromProblem(from);
      if (problem === null) continue;

      facts.push({
        from,
        problem,
        location: { kind: "source", file, line: from.line, col: 1 },
        configLocation: {
          kind: "config",
          file,
          json_pointer: `/FROM/${from.line}`,
        },
        hasAnyDigestInFile: hasAnyDigest,
        totalStagesInFile: froms.length,
        pinnedStagesInFile: pinnedCount,
      });
    }
  }

  return { facts, scannedFiles };
}

// ─── File discovery ────────────────────────────────────────────────────────

/**
 * Return candidate Dockerfile inputs. Rules:
 *   - If source_files is provided, pick every entry whose basename starts
 *     with "Dockerfile" (case-insensitive).
 *   - Else if source_code is provided and contains a FROM directive at the
 *     start of a line, treat the whole blob as a degraded Dockerfile.
 *   - Else return empty.
 */
function collectCandidateFiles(context: AnalysisContext): Array<[string, string]> {
  const out: Array<[string, string]> = [];

  if (context.source_files && context.source_files.size > 0) {
    for (const [path, text] of context.source_files) {
      if (isDockerfilePath(path)) {
        out.push([path, text]);
      }
    }
    return out;
  }

  if (context.source_code && looksLikeDockerfileBlob(context.source_code)) {
    out.push(["<concatenated-source>", context.source_code]);
  }
  return out;
}

function isDockerfilePath(path: string): boolean {
  // Take the basename without regex. Portable split on `/` or `\`.
  const lastSlash = Math.max(path.lastIndexOf("/"), path.lastIndexOf("\\"));
  const basename = lastSlash >= 0 ? path.slice(lastSlash + 1) : path;
  const lower = basename.toLowerCase();
  return lower === "dockerfile" || lower.startsWith("dockerfile.");
}

function looksLikeDockerfileBlob(text: string): boolean {
  // Cheap line-scan — no regex. Looks for any line whose first token
  // (after whitespace) is FROM (any case).
  const lines = text.split("\n");
  for (const line of lines) {
    const trimmed = line.trimStart();
    if (trimmed.length >= 4) {
      const head = trimmed.slice(0, 4).toUpperCase();
      const next = trimmed.charAt(4);
      if (head === "FROM" && (next === " " || next === "\t")) return true;
    }
  }
  return false;
}

// ─── FROM parsing (token-based, no regex) ─────────────────────────────────

/**
 * Parse every FROM instruction in a Dockerfile. Tokenises each line into
 * whitespace-separated words, strips known flags, then interprets the
 * remaining tokens as:
 *   FROM [flags] image[:tag][@digest] [AS stage]
 * The parser is defensive — a malformed line yields no FromInstruction,
 * not a fabricated one.
 */
export function parseDockerfileFroms(file: string, source: string): FromInstruction[] {
  const lines = source.split("\n");
  const out: FromInstruction[] = [];

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];
    const trimmed = rawLine.trim();
    if (trimmed.length === 0) continue;
    // Skip comment lines.
    if (trimmed.startsWith("#")) continue;
    // Must start with FROM (case-insensitive).
    if (!startsWithKeyword(trimmed, "FROM")) continue;

    const parsed = parseFromLine(trimmed, i + 1, file);
    if (parsed !== null) out.push(parsed);
  }

  return out;
}

function startsWithKeyword(line: string, keyword: string): boolean {
  if (line.length < keyword.length + 1) return false;
  const head = line.slice(0, keyword.length).toUpperCase();
  if (head !== keyword) return false;
  const next = line.charAt(keyword.length);
  return next === " " || next === "\t";
}

function parseFromLine(line: string, lineNumber: number, _file: string): FromInstruction | null {
  // Tokenise on whitespace (Dockerfile FROM doesn't embed quoted whitespace
  // in image references). Hand-written to avoid a regex literal.
  const tokens = tokeniseOnWhitespace(line);
  if (tokens.length < 2) return null;
  if (tokens[0].toUpperCase() !== "FROM") return null;

  // Skip flags like --platform=linux/amd64 (charter lethal edge case #5).
  let idx = 1;
  while (idx < tokens.length && isFromFlag(tokens[idx])) idx++;
  if (idx >= tokens.length) return null;

  const imageRef = tokens[idx];
  idx++;

  // Optional AS clause.
  let stage: string | null = null;
  if (idx < tokens.length && tokens[idx].toUpperCase() === "AS") {
    if (idx + 1 < tokens.length) {
      stage = tokens[idx + 1];
    }
  }

  const { image, tag, digest } = splitImageRef(imageRef);
  const usesArgReference = containsArgReference(imageRef);

  return {
    file: _file,
    line: lineNumber,
    raw: line.length > 240 ? `${line.slice(0, 237)}...` : line,
    image,
    tag,
    digest,
    stage,
    usesArgReference,
  };
}

function isFromFlag(token: string): boolean {
  if (!token.startsWith("--")) return false;
  // Match against known flag prefixes (typed Record lookup).
  for (const prefix of Object.keys(FROM_FLAG_PREFIXES)) {
    if (token.startsWith(prefix)) return true;
  }
  // Any long flag that contains `=` — conservative flag skip.
  return token.includes("=");
}

/**
 * Split "registry/org/image:tag@sha256:digest" into parts. Tokenising
 * without regex: find the LAST `@` for digest, then the LAST `:` in the
 * pre-`@` portion for tag.
 */
export function splitImageRef(ref: string): { image: string; tag: string | null; digest: string | null } {
  let remainder = ref;
  let digest: string | null = null;

  const atIdx = remainder.lastIndexOf("@");
  if (atIdx >= 0) {
    const digestPart = remainder.slice(atIdx + 1);
    if (digestPart.startsWith("sha256:") || digestPart.startsWith("sha512:")) {
      digest = digestPart;
      remainder = remainder.slice(0, atIdx);
    }
  }

  // Don't mistake `registry:5000/image` as `image:tag`. The heuristic: a colon
  // introduces a tag only if it appears AFTER the last `/` in the remainder.
  let tag: string | null = null;
  const lastSlash = remainder.lastIndexOf("/");
  const colonSearchFrom = lastSlash >= 0 ? lastSlash : 0;
  const tagColon = remainder.indexOf(":", colonSearchFrom);
  let image = remainder;
  if (tagColon >= 0) {
    image = remainder.slice(0, tagColon);
    tag = remainder.slice(tagColon + 1);
  }

  return { image, tag, digest };
}

function containsArgReference(ref: string): boolean {
  // Dockerfile argument references: $VAR or ${VAR}
  // Detect without regex: presence of '$' with any following alphanum/`{`.
  for (let i = 0; i < ref.length; i++) {
    if (ref.charCodeAt(i) !== 36 /* $ */) continue;
    if (i + 1 >= ref.length) continue;
    const next = ref.charAt(i + 1);
    if (next === "{" || isAsciiAlpha(next) || next === "_") return true;
  }
  return false;
}

function isAsciiAlpha(ch: string): boolean {
  if (ch.length !== 1) return false;
  const code = ch.charCodeAt(0);
  return (code >= 65 && code <= 90) || (code >= 97 && code <= 122);
}

/** Whitespace tokeniser — splits on space / tab runs, drops empties. */
function tokeniseOnWhitespace(line: string): string[] {
  const out: string[] = [];
  let cur = "";
  for (let i = 0; i < line.length; i++) {
    const ch = line.charAt(i);
    if (ch === " " || ch === "\t") {
      if (cur.length > 0) {
        out.push(cur);
        cur = "";
      }
    } else {
      cur += ch;
    }
  }
  if (cur.length > 0) out.push(cur);
  return out;
}

/** Delimiters used by Docker tag tokenisation. */
const TAG_DELIMITERS: Record<string, true> = { "-": true, "_": true, ".": true };

/** Split a string on any character in the delimiter set. Drops empties. */
function splitOnDelimiters(input: string, delimiters: Record<string, true>): string[] {
  const out: string[] = [];
  let cur = "";
  for (let i = 0; i < input.length; i++) {
    const ch = input.charAt(i);
    if (Object.prototype.hasOwnProperty.call(delimiters, ch)) {
      if (cur.length > 0) {
        out.push(cur);
        cur = "";
      }
    } else {
      cur += ch;
    }
  }
  if (cur.length > 0) out.push(cur);
  return out;
}

// ─── Problem classification ─────────────────────────────────────────────────

/**
 * Given a parsed FROM instruction, decide whether it represents a supply-
 * chain risk worth a finding. Order of evaluation matters — digest-pinned
 * images are accepted even if the tag also appears mutable, because the
 * digest is the authoritative pin.
 */
export function classifyFromProblem(from: FromInstruction): FromProblem {
  // Safe: the scratch empty base (exact match, case-sensitive).
  if (from.image === SCRATCH_IMAGE_LITERAL && from.digest === null && from.tag === null) {
    return null;
  }
  // Safe: digest-pinned (the authoritative pin).
  if (from.digest !== null && from.digest.length > 0) return null;

  // Unsafe: ARG-referenced base image (charter lethal edge case #2).
  if (from.usesArgReference) {
    return {
      kind: "arg-reference",
      detail:
        `Base image "${from.image}" contains an ARG reference — build-time argument ` +
        `substitution can silently swap the base image.`,
    };
  }

  // Unsafe: no tag at all (defaults to :latest).
  if (from.tag === null) {
    return {
      kind: "no-tag",
      detail: `Base image "${from.image}" has no tag and defaults to :latest.`,
    };
  }

  // Unsafe: mutable tag (token-split lookup).
  const mutableKeyword = detectMutableTagKeyword(from.tag);
  if (mutableKeyword !== null) {
    return {
      kind: "mutable-tag",
      matchedKeyword: mutableKeyword,
      detail:
        `Base image "${from.image}:${from.tag}" uses a mutable tag — the keyword ` +
        `"${mutableKeyword}" resolves to a moving target.`,
    };
  }

  return null;
}

/**
 * Split a tag on `-`, `_`, and `.` and look up each token in
 * MUTABLE_TAG_KEYWORDS (case-insensitive). Returns the first matched
 * keyword or null.
 *
 * Charter lethal edge case #4: catches "latest-prod", "lts-stable",
 * "release-latest" by tokenisation rather than equality.
 */
export function detectMutableTagKeyword(tag: string): string | null {
  const lower = tag.toLowerCase();
  const tokens = splitOnDelimiters(lower, TAG_DELIMITERS);
  for (const token of tokens) {
    if (Object.prototype.hasOwnProperty.call(MUTABLE_TAG_KEYWORDS, token)) {
      return MUTABLE_TAG_KEYWORDS[token].keyword;
    }
  }
  return null;
}
