/**
 * P4 evidence gathering — TLS-bypass pattern detection.
 *
 * No regex literals. All patterns live in ./data/bypass-patterns.ts.
 * Matching is boundary-aware string scanning per pattern match kind.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  BYPASS_PATTERNS,
  AMPLIFIER_TOKENS,
  type BypassPattern,
} from "./data/bypass-patterns.js";

export interface P4Hit {
  pattern: BypassPattern;
  file: string;
  line: number;
  observed: string;
  location: Location;
  configLocation: Location;
  amplifierPresent: boolean;
}

export interface P4Gathered {
  hits: P4Hit[];
  scannedFiles: string[];
}

export function gatherP4(context: AnalysisContext): P4Gathered {
  const hits: P4Hit[] = [];
  const scannedFiles: string[] = [];

  const files = collectCandidateFiles(context);
  for (const [file, text] of files) {
    scannedFiles.push(file);
    const amplifierInFile = detectAmplifier(text);
    const lines = text.split("\n");
    scanLines(file, lines, amplifierInFile, hits);
  }

  return { hits, scannedFiles };
}

function scanLines(
  file: string,
  lines: string[],
  amplifier: boolean,
  hits: P4Hit[],
): void {
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.trim();
    if (trimmed.length === 0) continue;
    if (trimmed.startsWith("#") || trimmed.startsWith("//")) continue;

    for (const pattern of Object.values(BYPASS_PATTERNS)) {
      if (!matchesPattern(pattern, raw)) continue;
      hits.push({
        pattern,
        file,
        line: i + 1,
        observed: capObserved(trimmed),
        location: { kind: "source", file, line: i + 1, col: 1 },
        configLocation: {
          kind: "config",
          file,
          json_pointer: `/tls/${pattern.id}`,
        },
        amplifierPresent: amplifier,
      });
    }
  }
}

function capObserved(line: string): string {
  return line.length > 180 ? `${line.slice(0, 177)}...` : line;
}

function matchesPattern(pattern: BypassPattern, rawLine: string): boolean {
  switch (pattern.matchKind) {
    case "kv-false":
      return matchKvValue(rawLine, pattern.key, "false");
    case "kv-true":
      return matchKvValue(rawLine, pattern.key, "true");
    case "kv-zero-string":
      return matchKvValue(rawLine, pattern.key, "0");
    case "bare-token":
      return matchBareToken(rawLine, pattern.key);
    case "cli-insecure-flag":
      return matchCliFlag(rawLine, pattern.key);
  }
}

function matchKvValue(rawLine: string, key: string, expectedValue: string): boolean {
  const lower = rawLine.toLowerCase();
  const lowerKey = key.toLowerCase();
  let idx = 0;
  while (idx < lower.length) {
    const found = lower.indexOf(lowerKey, idx);
    if (found < 0) return false;
    const before = found === 0 ? "" : lower.charAt(found - 1);
    if (!isKeyLeftBoundary(before)) {
      idx = found + 1;
      continue;
    }
    const afterKey = found + lowerKey.length;
    let p = afterKey;
    while (p < lower.length && (lower.charAt(p) === " " || lower.charAt(p) === "\t")) p++;
    if (p >= lower.length) return false;
    const sep = lower.charAt(p);
    if (sep !== ":" && sep !== "=") {
      idx = found + 1;
      continue;
    }
    p++;
    while (p < lower.length && (lower.charAt(p) === " " || lower.charAt(p) === "\t" || lower.charAt(p) === "\"" || lower.charAt(p) === "'")) p++;
    let end = p;
    while (end < lower.length && !isValueRightBoundary(lower.charAt(end))) end++;
    const value = lower.slice(p, end).trim();
    if (value === expectedValue) return true;
    idx = found + 1;
  }
  return false;
}

function matchBareToken(rawLine: string, token: string): boolean {
  const lower = rawLine.toLowerCase();
  const needle = token.toLowerCase();
  let idx = 0;
  while (idx < lower.length) {
    const found = lower.indexOf(needle, idx);
    if (found < 0) return false;
    const before = found === 0 ? "" : lower.charAt(found - 1);
    const rightIdx = found + needle.length;
    const right = rightIdx >= lower.length ? "" : lower.charAt(rightIdx);
    if (isTokenBoundary(before) && isTokenBoundary(right)) return true;
    idx = found + needle.length;
  }
  return false;
}

function matchCliFlag(rawLine: string, flag: string): boolean {
  const lower = rawLine.toLowerCase();
  const lowerFlag = flag.toLowerCase();
  let idx = 0;
  while (idx < lower.length) {
    const found = lower.indexOf(lowerFlag, idx);
    if (found < 0) return false;
    const before = found === 0 ? "" : lower.charAt(found - 1);
    if (before !== "" && before !== " " && before !== "\t" && before !== "\"" && before !== "'") {
      idx = found + lowerFlag.length;
      continue;
    }
    const rightIdx = found + lowerFlag.length;
    const right = rightIdx >= lower.length ? "" : lower.charAt(rightIdx);
    // Ensure boundary — either end-of-line / space / equals / quote.
    if (right === "" || right === " " || right === "\t" || right === "=" || right === "\"" || right === "'" || right === "\n") {
      return true;
    }
    idx = found + lowerFlag.length;
  }
  return false;
}

function isKeyLeftBoundary(ch: string): boolean {
  if (ch === "") return true;
  if (ch === " " || ch === "\t" || ch === "\n") return true;
  if (ch === "{" || ch === "," || ch === "(" || ch === "[") return true;
  if (ch === "\"" || ch === "'") return true;
  if (ch === ".") return true; // process.env.NODE_TLS_REJECT_UNAUTHORIZED
  if (ch === ";") return true;
  return false;
}

function isValueRightBoundary(ch: string): boolean {
  return ch === " " || ch === "\t" || ch === "," || ch === "\"" || ch === "'" || ch === "]" || ch === "}" || ch === ")" || ch === "#" || ch === "\n" || ch === ";";
}

function isTokenBoundary(ch: string): boolean {
  if (ch === "") return true;
  if (ch === " " || ch === "\t" || ch === "\n") return true;
  if (ch === "(" || ch === ")" || ch === "," || ch === ";") return true;
  if (ch === "\"" || ch === "'") return true;
  if (ch === "[" || ch === "]" || ch === "{" || ch === "}") return true;
  return false;
}

function detectAmplifier(text: string): boolean {
  const lower = text.toLowerCase();
  for (const token of Object.keys(AMPLIFIER_TOKENS)) {
    if (lower.includes(token.toLowerCase())) return true;
  }
  return false;
}

// ─── Candidate file discovery ──────────────────────────────────────────────

function collectCandidateFiles(context: AnalysisContext): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  if (context.source_files && context.source_files.size > 0) {
    for (const [path, text] of context.source_files) {
      if (isCandidatePath(path)) out.push([path, text]);
    }
    if (out.length > 0) return out;
  }
  if (context.source_code) out.push(["<concatenated-source>", context.source_code]);
  return out;
}

function isCandidatePath(path: string): boolean {
  const lower = path.toLowerCase();
  if (lower.endsWith(".ts") || lower.endsWith(".tsx") || lower.endsWith(".js") || lower.endsWith(".jsx")) return true;
  if (lower.endsWith(".mts") || lower.endsWith(".cts") || lower.endsWith(".mjs") || lower.endsWith(".cjs")) return true;
  if (lower.endsWith(".py")) return true;
  if (lower.endsWith(".go") || lower.endsWith(".java")) return true;
  if (lower.endsWith(".sh")) return true;
  if (lower === "dockerfile" || lower.startsWith("dockerfile.")) return true;
  return false;
}
