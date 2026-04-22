/**
 * P6 evidence gathering — LD_PRELOAD / library-hijack / memory-injection
 * detection across Dockerfiles, systemd unit files, shell scripts, and
 * TypeScript / Python source.
 *
 * No regex literals. Patterns live in ./data/hijack-patterns.ts.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  HIJACK_PATTERNS,
  PATH_WRITE_TOKENS,
  type HijackPattern,
  type HijackVariant,
} from "./data/hijack-patterns.js";

export interface P6Hit {
  pattern: HijackPattern;
  file: string;
  line: number;
  observed: string;
  location: Location;
  configLocation: Location;
  /** Whether the detected target path is variable / attacker-controlled. */
  variablePath: boolean;
}

export interface P6Gathered {
  hits: P6Hit[];
  scannedFiles: string[];
}

export function gatherP6(context: AnalysisContext): P6Gathered {
  const hits: P6Hit[] = [];
  const scannedFiles: string[] = [];

  const files = collectCandidateFiles(context);
  for (const [file, text] of files) {
    scannedFiles.push(file);
    const lines = text.split("\n");
    scanLines(file, lines, hits);
  }

  return { hits, scannedFiles };
}

function scanLines(file: string, lines: string[], hits: P6Hit[]): void {
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.trim();
    if (trimmed.length === 0) continue;
    if (trimmed.startsWith("#") || trimmed.startsWith("//")) continue;

    for (const pattern of Object.values(HIJACK_PATTERNS)) {
      const result = matchPattern(pattern, raw);
      if (!result) continue;
      hits.push({
        pattern,
        file,
        line: i + 1,
        observed: capObserved(trimmed),
        location: { kind: "source", file, line: i + 1, col: 1 },
        configLocation: {
          kind: "config",
          file,
          json_pointer: `/hijack/${pattern.id}`,
        },
        variablePath: result.variablePath,
      });
    }
  }
}

function capObserved(line: string): string {
  return line.length > 180 ? `${line.slice(0, 177)}...` : line;
}

// ─── Pattern matching ──────────────────────────────────────────────────────

interface MatchResult {
  variablePath: boolean;
}

function matchPattern(pattern: HijackPattern, rawLine: string): MatchResult | null {
  switch (pattern.matchKind) {
    case "kv-nonempty":
      return matchKvNonEmpty(pattern, rawLine);
    case "literal-path":
      return matchLiteralPath(pattern, rawLine);
    case "function-call":
      return matchFunctionCall(pattern, rawLine);
    case "path-write":
      return matchLiteralPath(pattern, rawLine);
  }
}

function matchKvNonEmpty(pattern: HijackPattern, rawLine: string): MatchResult | null {
  // Case-sensitive key match; value must be non-empty.
  const key = pattern.key;
  let idx = 0;
  while (idx < rawLine.length) {
    const found = rawLine.indexOf(key, idx);
    if (found < 0) return null;
    const left = found === 0 ? "" : rawLine.charAt(found - 1);
    if (!isKeyLeftBoundary(left)) {
      idx = found + key.length;
      continue;
    }
    const afterKey = found + key.length;
    let p = afterKey;
    while (p < rawLine.length && (rawLine.charAt(p) === " " || rawLine.charAt(p) === "\t")) p++;
    if (p >= rawLine.length) return null;
    const sep = rawLine.charAt(p);
    if (sep !== "=" && sep !== ":") {
      idx = found + key.length;
      continue;
    }
    p++;
    while (p < rawLine.length && (rawLine.charAt(p) === " " || rawLine.charAt(p) === "\t" || rawLine.charAt(p) === "\"" || rawLine.charAt(p) === "'")) p++;
    let end = p;
    while (end < rawLine.length && !isValueRightBoundary(rawLine.charAt(end))) end++;
    const value = rawLine.slice(p, end).trim();
    if (value.length === 0) {
      idx = found + key.length;
      continue;
    }
    return { variablePath: valueIsVariable(value) };
  }
  return null;
}

function matchLiteralPath(pattern: HijackPattern, rawLine: string): MatchResult | null {
  // Case-sensitive token presence.
  const key = pattern.key;
  if (!rawLine.includes(key)) return null;
  // For /etc/ld.so.preload, confirm the line includes a write primitive (tee /
  // > redirect) — otherwise a read-only mention (AppArmor profile, docs)
  // produces noise.
  if (pattern.id === "ld-so-preload-file") {
    if (!lineHasWritePrimitive(rawLine)) return null;
  }
  // For /proc/ variant, require `/proc/<digits|$variable>/mem` or PID pattern.
  if (pattern.id === "proc-pid-mem") {
    if (!lineMentionsProcMem(rawLine)) return null;
  }
  // For PTRACE_ATTACH, require the attach flag on a ptrace call.
  if (pattern.id === "ptrace-attach") {
    if (!rawLine.includes("ptrace")) return null;
  }
  return { variablePath: pattern.variablePathPossible };
}

function matchFunctionCall(pattern: HijackPattern, rawLine: string): MatchResult | null {
  if (!rawLine.includes(pattern.key)) return null;
  // Require open-paren to treat this as a call site.
  const idx = rawLine.indexOf(pattern.key);
  const rightIdx = idx + pattern.key.length;
  if (rightIdx >= rawLine.length) return null;
  // Walk past any whitespace.
  let p = rightIdx;
  while (p < rawLine.length && (rawLine.charAt(p) === " " || rawLine.charAt(p) === "\t")) p++;
  if (rawLine.charAt(p) !== "(") return null;
  // Extract first argument up to comma / close-paren.
  p++;
  let end = p;
  while (end < rawLine.length && rawLine.charAt(end) !== "," && rawLine.charAt(end) !== ")") end++;
  const arg = rawLine.slice(p, end).trim();
  // Hard-coded string-literal with well-known lib → legitimate.
  if (argIsHardCodedTrustedLib(arg)) return null;
  return { variablePath: valueIsVariable(arg) };
}

function stripQuoteChars(s: string): string {
  let r = "";
  for (let i = 0; i < s.length; i++) {
    const ch = s.charAt(i);
    if (ch === "\"" || ch === "'" || ch === "`") continue;
    r += ch;
  }
  return r;
}

function argIsHardCodedTrustedLib(arg: string): boolean {
  const stripped = stripQuoteChars(arg).trim();
  const lower = stripped.toLowerCase();
  if (lower.startsWith("lib") && (lower.endsWith(".so") || lower.includes(".so."))) {
    // Hard-coded libssl / libcrypto / libc / libpthread / libm / libdl — trusted.
    if (lower.startsWith("libssl") || lower.startsWith("libcrypto")) return true;
    if (lower.startsWith("libc.") || lower.startsWith("libpthread") || lower.startsWith("libm.") || lower.startsWith("libdl.")) return true;
  }
  return false;
}

function valueIsVariable(value: string): boolean {
  const stripped = stripQuoteChars(value).trim();
  // Starts with $, ${, %, @, or looks like a bare identifier (no slash, no .so suffix).
  if (stripped.startsWith("$") || stripped.startsWith("%") || stripped.startsWith("@")) return true;
  if (stripped.includes("$")) return true;
  if (stripped.length === 0) return false;
  // Hard-coded absolute path to a .so is still a hijack (the library itself
  // is suspect), so treat it as NOT variable.
  if (stripped.startsWith("/") && (stripped.endsWith(".so") || stripped.includes(".so."))) return false;
  // Bare identifier with no slash → variable reference (not a literal path).
  if (!stripped.includes("/") && !stripped.includes("\\")) return true;
  return false;
}

function lineHasWritePrimitive(rawLine: string): boolean {
  for (const token of Object.keys(PATH_WRITE_TOKENS)) {
    if (rawLine.includes(token)) return true;
  }
  if (rawLine.includes(">")) return true;
  return false;
}

function lineMentionsProcMem(rawLine: string): boolean {
  // Look for /proc/<something>/mem
  const lower = rawLine.toLowerCase();
  const idx = lower.indexOf("/proc/");
  if (idx < 0) return false;
  return lower.includes("/mem", idx);
}

function isKeyLeftBoundary(ch: string): boolean {
  if (ch === "") return true;
  if (ch === " " || ch === "\t" || ch === "\n") return true;
  if (ch === "{" || ch === "," || ch === "(" || ch === "[") return true;
  if (ch === "\"" || ch === "'") return true;
  if (ch === "=") return true;
  return false;
}

function isValueRightBoundary(ch: string): boolean {
  return ch === " " || ch === "\t" || ch === "\"" || ch === "'" || ch === ";" || ch === "\n" || ch === ",";
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
  if (lower === "dockerfile" || lower.startsWith("dockerfile.")) return true;
  if (lower.endsWith(".yaml") || lower.endsWith(".yml")) return true;
  if (lower.endsWith(".service") || lower.endsWith(".socket")) return true;
  if (lower.endsWith(".sh")) return true;
  if (lower.endsWith(".ts") || lower.endsWith(".tsx") || lower.endsWith(".js") || lower.endsWith(".jsx")) return true;
  if (lower.endsWith(".mts") || lower.endsWith(".cts") || lower.endsWith(".mjs") || lower.endsWith(".cjs")) return true;
  if (lower.endsWith(".py")) return true;
  if (lower.endsWith(".c") || lower.endsWith(".cpp") || lower.endsWith(".h") || lower.endsWith(".hpp")) return true;
  return false;
}

// Re-export for downstream callers.
export type { HijackVariant };
