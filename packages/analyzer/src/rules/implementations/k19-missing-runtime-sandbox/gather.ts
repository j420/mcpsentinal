/**
 * K19 evidence gathering — line-oriented tokenisation of YAML / Dockerfile /
 * shell launch scripts to locate sandbox-disable flags.
 *
 * No regex literals. No string-literal arrays > 5. All canonical flag lists
 * live in `./data/sandbox-flags.ts` as typed Records.
 *
 * Strategy:
 *   1. For every candidate file (source_files map, or concatenated source),
 *      iterate lines.
 *   2. Skip pure comment lines (start with '#' or '//' after whitespace trim).
 *   3. For each non-comment line:
 *        a. Tokenise on whitespace and on `=` (shell / CLI flags).
 *        b. For each CLI-flag entry in SANDBOX_FLAGS, check whether the
 *           line contains the flag as a standalone token.
 *        c. For each kv-true / kv-value entry, extract the (key, value)
 *           pair by splitting on the first ':' or '=' and compare
 *           case-insensitively.
 *        d. For capability-add patterns, recognise both --cap-add=CAP and
 *           YAML-list shapes (`- CAP` indented under `add:`).
 *   4. Collect compensating-control presence separately.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  SANDBOX_FLAGS,
  DANGEROUS_CAPABILITIES,
  COMPENSATING_CONTROL_KEYS,
  type SandboxFlag,
  type FlagCategory,
} from "./data/sandbox-flags.js";

// ─── Public types ──────────────────────────────────────────────────────────

export interface K19FlagHit {
  flag: SandboxFlag;
  file: string;
  line: number;
  /** Verbatim line, trimmed and length-capped. */
  observed: string;
  /** Structured source-kind Location at (file, line). */
  location: Location;
  /** config-kind Location for json_pointer-style config pin. */
  configLocation: Location;
  /** When the flag is a capability addition, the specific capability matched. */
  capabilityMatched?: string;
}

export interface K19Gathered {
  hits: K19FlagHit[];
  /** Files in which compensating controls (runAsNonRoot, readOnlyRootFilesystem, no-new-privileges) were observed. */
  compensationPerFile: Map<string, Set<string>>;
  /** Files that were actually scanned. */
  scannedFiles: string[];
}

// ─── Entry point ───────────────────────────────────────────────────────────

export function gatherK19(context: AnalysisContext): K19Gathered {
  const hits: K19FlagHit[] = [];
  const compensationPerFile = new Map<string, Set<string>>();
  const scannedFiles: string[] = [];

  const files = collectCandidateFiles(context);
  for (const [file, text] of files) {
    scannedFiles.push(file);
    const lines = text.split("\n");

    // Track compensation per file.
    const compSet = new Set<string>();

    // YAML-structure state: are we currently inside an `add:` list under a
    // `capabilities:` key? Used for the YAML-list cap-add variant (charter
    // lethal edge case #2).
    let inCapsAddList = false;
    let capsAddBaseIndent = -1;

    for (let i = 0; i < lines.length; i++) {
      const rawLine = lines[i];
      const lineNumber = i + 1;
      const trimmedFull = rawLine.trim();
      if (trimmedFull.length === 0) {
        inCapsAddList = false;
        continue;
      }
      // Skip pure comment lines (charter lethal edge case #5).
      const noCommentLine = stripLineForComment(trimmedFull);
      if (noCommentLine === null) continue;

      // Track `capabilities: { add: [...] }` / block variants.
      const capAddState = detectCapAddContext(rawLine, inCapsAddList, capsAddBaseIndent);
      inCapsAddList = capAddState.inList;
      capsAddBaseIndent = capAddState.baseIndent;

      // Compensating controls first (cheap scan).
      for (const key of Object.keys(COMPENSATING_CONTROL_KEYS)) {
        if (containsKvWithTrueValue(noCommentLine, key)) {
          compSet.add(key);
        }
      }

      // Dispatch per flag.
      for (const flag of Object.values(SANDBOX_FLAGS)) {
        const hit = matchFlagOnLine(flag, noCommentLine, rawLine);
        if (!hit) continue;
        hits.push({
          flag,
          file,
          line: lineNumber,
          observed: capObservedText(noCommentLine),
          location: { kind: "source", file, line: lineNumber, col: 1 },
          configLocation: {
            kind: "config",
            file,
            json_pointer: `/securityContext/${flag.id}`,
          },
        });
      }

      // Capability add — independent of the flag registry.
      const capMatches = extractDangerousCapabilities(rawLine, inCapsAddList);
      for (const cap of capMatches) {
        const capInfo = DANGEROUS_CAPABILITIES[cap];
        if (!capInfo) continue;
        hits.push({
          flag: {
            id: `cap-add-${cap.toLowerCase()}`,
            matchKind: "cap-add",
            key: cap,
            category: "capability-addition",
            description: capInfo.description,
            weight: capInfo.weight,
          },
          file,
          line: lineNumber,
          observed: capObservedText(noCommentLine),
          location: { kind: "source", file, line: lineNumber, col: 1 },
          configLocation: {
            kind: "config",
            file,
            json_pointer: `/securityContext/capabilities/add/${cap}`,
          },
          capabilityMatched: cap,
        });
      }

      // readOnlyRootFilesystem: false  → sandbox defeat (inverted-true flag)
      if (containsKvWithFalseValue(noCommentLine, "readOnlyRootFilesystem")) {
        const flag = SANDBOX_FLAGS["read-only-root-fs-false"];
        hits.push({
          flag,
          file,
          line: lineNumber,
          observed: capObservedText(noCommentLine),
          location: { kind: "source", file, line: lineNumber, col: 1 },
          configLocation: {
            kind: "config",
            file,
            json_pointer: `/securityContext/${flag.id}`,
          },
        });
      }
    }

    if (compSet.size > 0) compensationPerFile.set(file, compSet);
  }

  return { hits, compensationPerFile, scannedFiles };
}

// ─── File discovery ────────────────────────────────────────────────────────

function collectCandidateFiles(context: AnalysisContext): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  if (context.source_files && context.source_files.size > 0) {
    for (const [path, text] of context.source_files) {
      if (isContainerConfigPath(path)) out.push([path, text]);
    }
    if (out.length > 0) return out;
  }
  if (context.source_code) {
    out.push(["<concatenated-source>", context.source_code]);
  }
  return out;
}

function isContainerConfigPath(path: string): boolean {
  const lastSlash = Math.max(path.lastIndexOf("/"), path.lastIndexOf("\\"));
  const basename = lastSlash >= 0 ? path.slice(lastSlash + 1) : path;
  const lower = basename.toLowerCase();
  if (lower === "dockerfile" || lower.startsWith("dockerfile.")) return true;
  if (lower === "docker-compose.yml" || lower === "docker-compose.yaml") return true;
  if (lower === "compose.yml" || lower === "compose.yaml") return true;
  if (lower.endsWith(".yaml") || lower.endsWith(".yml")) return true;
  if (lower.endsWith(".sh")) return true;
  if (lower.endsWith(".ts") || lower.endsWith(".js") || lower.endsWith(".py")) return true;
  return false;
}

// ─── Line-level helpers ────────────────────────────────────────────────────

function stripLineForComment(trimmedLine: string): string | null {
  if (trimmedLine.startsWith("#")) return null;
  if (trimmedLine.startsWith("//")) return null;
  // Otherwise keep the line — inline comments (YAML `key: value  # note`) are
  // still signal.
  return trimmedLine;
}

function capObservedText(line: string): string {
  return line.length > 180 ? `${line.slice(0, 177)}...` : line;
}

/**
 * Case-insensitive token containment — does the line contain `needle` as a
 * word-like token (bounded by whitespace, =, :, quote, or line edge)?
 */
function containsStandaloneToken(line: string, needle: string): boolean {
  const lowerLine = line.toLowerCase();
  const lowerNeedle = needle.toLowerCase();
  let idx = 0;
  while (idx < lowerLine.length) {
    const found = lowerLine.indexOf(lowerNeedle, idx);
    if (found < 0) return false;
    const before = found === 0 ? "" : lowerLine.charAt(found - 1);
    const afterIdx = found + lowerNeedle.length;
    const after = afterIdx >= lowerLine.length ? "" : lowerLine.charAt(afterIdx);
    if (isTokenBoundary(before) && isTokenBoundary(after)) return true;
    idx = found + 1;
  }
  return false;
}

function isTokenBoundary(ch: string): boolean {
  if (ch === "") return true;
  if (ch === " " || ch === "\t") return true;
  if (ch === "=" || ch === ":" || ch === ",") return true;
  if (ch === '"' || ch === "'") return true;
  if (ch === "[" || ch === "]" || ch === "{" || ch === "}") return true;
  return false;
}

/**
 * Match a SandboxFlag against a single line. Handles all four match kinds.
 */
function matchFlagOnLine(flag: SandboxFlag, lineNoComment: string, rawLine: string): boolean {
  switch (flag.matchKind) {
    case "cli-flag":
      return containsStandaloneToken(lineNoComment, flag.key);
    case "kv-true":
      if (flag.key === "readOnlyRootFilesystem-inverted") return false; // handled separately
      return containsKvWithTrueValue(lineNoComment, flag.key);
    case "kv-value":
      if (!flag.trigger) return false;
      return containsKvWithSpecificValue(lineNoComment, flag.key, flag.trigger);
    case "cap-add":
      return false; // handled separately via extractDangerousCapabilities
  }
}

/** Does `line` express `key: true` / `key=true` / `key true` / `"key": true`? */
function containsKvWithTrueValue(line: string, key: string): boolean {
  return containsKvMatchingValue(line, key, (v) => {
    const low = v.toLowerCase();
    return low === "true" || low === "yes" || low === "1";
  });
}

function containsKvWithFalseValue(line: string, key: string): boolean {
  return containsKvMatchingValue(line, key, (v) => {
    const low = v.toLowerCase();
    return low === "false" || low === "no" || low === "0";
  });
}

function containsKvWithSpecificValue(line: string, key: string, value: string): boolean {
  const wantLower = value.toLowerCase();
  return containsKvMatchingValue(line, key, (v) => v.toLowerCase() === wantLower);
}

/**
 * Generic KV matcher. Splits the line on the first `:` or `=` after the key
 * token; applies the value predicate to the RHS (stripped of quotes).
 */
function containsKvMatchingValue(
  line: string,
  key: string,
  valuePredicate: (value: string) => boolean,
): boolean {
  const lowerLine = line.toLowerCase();
  const lowerKey = key.toLowerCase();
  let idx = 0;
  while (idx < lowerLine.length) {
    const found = lowerLine.indexOf(lowerKey, idx);
    if (found < 0) return false;
    const before = found === 0 ? "" : lowerLine.charAt(found - 1);
    const afterKey = found + lowerKey.length;
    if (!isKeyStartBoundary(before)) {
      idx = found + 1;
      continue;
    }
    // Skip whitespace after key, then expect ':' or '='.
    let p = afterKey;
    while (p < lowerLine.length && (lowerLine.charAt(p) === " " || lowerLine.charAt(p) === "\t")) p++;
    if (p >= lowerLine.length || (lowerLine.charAt(p) !== ":" && lowerLine.charAt(p) !== "=")) {
      idx = found + 1;
      continue;
    }
    p++;
    // Skip whitespace, quotes.
    while (p < lowerLine.length && (lowerLine.charAt(p) === " " || lowerLine.charAt(p) === "\t" || lowerLine.charAt(p) === '"' || lowerLine.charAt(p) === "'")) p++;
    // Read value token.
    let valueEnd = p;
    while (
      valueEnd < lowerLine.length &&
      !isTokenBoundary(lowerLine.charAt(valueEnd)) &&
      lowerLine.charAt(valueEnd) !== "#"
    ) {
      valueEnd++;
    }
    const value = line.slice(p, valueEnd).trim();
    if (value.length > 0 && valuePredicate(value)) return true;
    idx = found + 1;
  }
  return false;
}

function isKeyStartBoundary(ch: string): boolean {
  if (ch === "") return true;
  if (ch === " " || ch === "\t") return true;
  if (ch === "-" || ch === "{") return true; // YAML list item prefix; JSON-style
  if (ch === '"' || ch === "'") return true;
  return false;
}

// ─── Capability-add extraction ─────────────────────────────────────────────

interface CapAddState {
  inList: boolean;
  baseIndent: number;
}

/**
 * Track whether a line opens a YAML `add:` block under a `capabilities:`
 * parent. A line that contains both `capabilities:` and `add:` inline
 * (flow style) does NOT open a block list.
 */
function detectCapAddContext(
  rawLine: string,
  currentInList: boolean,
  currentBaseIndent: number,
): CapAddState {
  const indent = leadingIndent(rawLine);
  const trimmed = rawLine.trim();

  // Block opener: line ends with `add:` (nothing after).
  if (endsWithKeyOnly(trimmed, "add")) {
    return { inList: true, baseIndent: indent };
  }

  if (currentInList) {
    // Leaving the list: indent dropped back to or below opener indent.
    if (indent <= currentBaseIndent && trimmed.length > 0 && !trimmed.startsWith("-")) {
      return { inList: false, baseIndent: -1 };
    }
    return { inList: true, baseIndent: currentBaseIndent };
  }

  return { inList: false, baseIndent: -1 };
}

function leadingIndent(line: string): number {
  let i = 0;
  while (i < line.length && (line.charAt(i) === " " || line.charAt(i) === "\t")) i++;
  return i;
}

function endsWithKeyOnly(trimmed: string, key: string): boolean {
  const lower = trimmed.toLowerCase();
  if (lower === `${key}:`) return true;
  // Allow leading YAML list indicator.
  if (lower === `- ${key}:`) return true;
  return false;
}

/**
 * Extract dangerous capability names from a line. Handles:
 *   - --cap-add=SYS_ADMIN
 *   - --cap-add SYS_ADMIN
 *   - capabilities: { add: [SYS_ADMIN] }   (flow YAML)
 *   - `- SYS_ADMIN` under an `add:` block (handled via inCapsAddList)
 */
function extractDangerousCapabilities(rawLine: string, inCapsAddList: boolean): string[] {
  const out: string[] = [];
  const line = rawLine;

  // --cap-add=VAL or --cap-add VAL
  const capFlag = "--cap-add";
  let searchFrom = 0;
  while (searchFrom < line.length) {
    const idx = line.indexOf(capFlag, searchFrom);
    if (idx < 0) break;
    const boundBefore = idx === 0 ? "" : line.charAt(idx - 1);
    if (!isTokenBoundary(boundBefore)) {
      searchFrom = idx + capFlag.length;
      continue;
    }
    const after = line.slice(idx + capFlag.length);
    const val = readFirstValue(after);
    if (val !== null) {
      const upper = val.toUpperCase();
      if (Object.prototype.hasOwnProperty.call(DANGEROUS_CAPABILITIES, upper)) out.push(upper);
    }
    searchFrom = idx + capFlag.length;
  }

  // Flow-style YAML: capabilities: { add: [SYS_ADMIN, NET_RAW] }
  const flowOpen = line.indexOf("add:");
  if (flowOpen >= 0) {
    const bracketStart = line.indexOf("[", flowOpen);
    if (bracketStart > flowOpen) {
      const bracketEnd = line.indexOf("]", bracketStart);
      if (bracketEnd > bracketStart) {
        const caps = line.slice(bracketStart + 1, bracketEnd);
        const items = splitFlowList(caps);
        for (const it of items) {
          const upper = it.trim().toUpperCase();
          if (Object.prototype.hasOwnProperty.call(DANGEROUS_CAPABILITIES, upper)) out.push(upper);
        }
      }
    }
  }

  // Block-style YAML list under `add:` — we are inside the block.
  if (inCapsAddList) {
    const trimmed = line.trim();
    if (trimmed.startsWith("- ")) {
      const val = trimmed.slice(2).trim();
      const upper = stripQuotes(val).toUpperCase();
      if (Object.prototype.hasOwnProperty.call(DANGEROUS_CAPABILITIES, upper)) out.push(upper);
    }
  }

  return Array.from(new Set(out));
}

function readFirstValue(rest: string): string | null {
  let i = 0;
  // Skip leading `=`, whitespace, quotes.
  while (i < rest.length && (rest.charAt(i) === "=" || rest.charAt(i) === " " || rest.charAt(i) === "\t" || rest.charAt(i) === '"' || rest.charAt(i) === "'")) i++;
  if (i >= rest.length) return null;
  let end = i;
  while (end < rest.length && !isTokenBoundary(rest.charAt(end))) end++;
  const val = rest.slice(i, end).trim();
  return val.length > 0 ? val : null;
}

function splitFlowList(text: string): string[] {
  const out: string[] = [];
  let cur = "";
  for (let i = 0; i < text.length; i++) {
    const ch = text.charAt(i);
    if (ch === ",") {
      if (cur.length > 0) out.push(cur);
      cur = "";
    } else {
      cur += ch;
    }
  }
  if (cur.length > 0) out.push(cur);
  return out.map(stripQuotes);
}

function stripQuotes(s: string): string {
  let r = s.trim();
  if (r.length >= 2) {
    const first = r.charAt(0);
    const last = r.charAt(r.length - 1);
    if ((first === '"' && last === '"') || (first === "'" && last === "'")) {
      r = r.slice(1, r.length - 1);
    }
  }
  return r;
}

// ─── Exports consumed by verification / index ─────────────────────────────

export type { FlagCategory };
