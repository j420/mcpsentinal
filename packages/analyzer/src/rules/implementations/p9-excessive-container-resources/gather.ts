/**
 * P9 evidence gathering — line-oriented resource-limit detection.
 *
 * No regex literals. All token lists live in ./data/resource-flags.ts.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  RESOURCE_KEYS,
  UNLIMITED_SENTINELS,
  MEMORY_UNITS,
  type ResourceKey,
  type ResourceKind,
} from "./data/resource-flags.js";

export interface P9FlagHit {
  rule: ResourceKey;
  file: string;
  line: number;
  observed: string;
  /** Source-kind Location at (file, line). */
  location: Location;
  /** config-kind Location with json pointer. */
  configLocation: Location;
  /** For excessive-value hits, the detected magnitude (parsed). */
  magnitude?: number;
}

export interface P9Gathered {
  hits: P9FlagHit[];
  /** Files where `requests.<kind>` IS set (to be reported alongside missing `limits`). */
  requestsPerFile: Map<string, Set<ResourceKind>>;
  scannedFiles: string[];
}

export function gatherP9(context: AnalysisContext): P9Gathered {
  const hits: P9FlagHit[] = [];
  const requestsPerFile = new Map<string, Set<ResourceKind>>();
  const scannedFiles: string[] = [];

  const files = collectCandidateFiles(context);
  for (const [file, text] of files) {
    scannedFiles.push(file);
    const lines = text.split("\n");
    const requests = new Set<ResourceKind>();

    for (let i = 0; i < lines.length; i++) {
      const raw = lines[i];
      const trimmed = raw.trim();
      if (trimmed.length === 0) continue;
      if (trimmed.startsWith("#") || trimmed.startsWith("//")) continue;

      // requests.* tracking for mitigation reporting (lethal edge case #1).
      const reqKind = detectRequestsKind(raw);
      if (reqKind !== null) requests.add(reqKind);

      for (const rule of Object.values(RESOURCE_KEYS)) {
        const hit = evaluateRule(rule, raw, trimmed);
        if (hit === null) continue;
        hits.push({
          rule,
          file,
          line: i + 1,
          observed: capObserved(trimmed),
          location: { kind: "source", file, line: i + 1, col: 1 },
          configLocation: {
            kind: "config",
            file,
            json_pointer: `/resources/${rule.id}`,
          },
          magnitude: hit.magnitude,
        });
      }
    }

    if (requests.size > 0) requestsPerFile.set(file, requests);
  }

  return { hits, requestsPerFile, scannedFiles };
}

// ─── Candidates ────────────────────────────────────────────────────────────

function collectCandidateFiles(context: AnalysisContext): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  if (context.source_files && context.source_files.size > 0) {
    for (const [path, text] of context.source_files) {
      if (isResourceConfigPath(path)) out.push([path, text]);
    }
    if (out.length > 0) return out;
  }
  if (context.source_code) out.push(["<concatenated-source>", context.source_code]);
  return out;
}

function isResourceConfigPath(path: string): boolean {
  const lastSlash = Math.max(path.lastIndexOf("/"), path.lastIndexOf("\\"));
  const basename = lastSlash >= 0 ? path.slice(lastSlash + 1) : path;
  const lower = basename.toLowerCase();
  if (lower === "dockerfile" || lower.startsWith("dockerfile.")) return true;
  if (lower === "docker-compose.yml" || lower === "docker-compose.yaml") return true;
  if (lower === "compose.yml" || lower === "compose.yaml") return true;
  if (lower.endsWith(".yaml") || lower.endsWith(".yml")) return true;
  if (lower.endsWith(".sh")) return true;
  return false;
}

function capObserved(line: string): string {
  return line.length > 180 ? `${line.slice(0, 177)}...` : line;
}

// ─── Request tracking ──────────────────────────────────────────────────────

function detectRequestsKind(rawLine: string): ResourceKind | null {
  // Very approximate: a line like `  memory: 512Mi` inside a `requests:` block.
  // We cannot track YAML nesting without a parser — use a marker heuristic:
  // flag lines that are adjacent to a `requests:` line, OR contain "requests.memory".
  // This is best-effort mitigation signal, not a finding trigger.
  const lower = rawLine.toLowerCase();
  if (lower.includes("requests") && lower.includes("memory")) return "memory";
  if (lower.includes("requests") && (lower.includes("cpu") || lower.includes("millicpus"))) return "cpu";
  return null;
}

// ─── Rule evaluation ───────────────────────────────────────────────────────

function evaluateRule(
  rule: ResourceKey,
  rawLine: string,
  _trimmed: string,
): { magnitude?: number } | null {
  switch (rule.matchKind) {
    case "unlimited-sentinel":
      return checkUnlimitedSentinel(rule, rawLine);
    case "excessive-value":
      return checkExcessiveValue(rule, rawLine);
    case "cli-zero":
      return checkCliZero(rule, rawLine);
  }
}

function checkUnlimitedSentinel(rule: ResourceKey, rawLine: string): { magnitude?: number } | null {
  const value = extractKvValue(rawLine, rule.key);
  if (value === null) return null;
  const lower = stripQuotesTrim(value).toLowerCase();
  if (Object.prototype.hasOwnProperty.call(UNLIMITED_SENTINELS, lower)) return {};
  if (lower === "0") return {};
  return null;
}

function checkExcessiveValue(rule: ResourceKey, rawLine: string): { magnitude?: number } | null {
  const value = extractKvValue(rawLine, rule.key);
  if (value === null) return null;
  const stripped = stripQuotesTrim(value);
  // Parse "<number><unit>" where unit is Gi / GiB / GB / G (case-insensitive).
  const { number, unit } = splitNumberUnit(stripped);
  if (number === null) return null;
  if (!unit) return null;
  const unitLower = unit.toLowerCase();
  if (!rule.excessiveUnits || !Object.prototype.hasOwnProperty.call(rule.excessiveUnits, unitLower)) return null;
  if (rule.excessiveThreshold === undefined) return null;
  if (number <= rule.excessiveThreshold) return null;
  return { magnitude: number };
}

function checkCliZero(rule: ResourceKey, rawLine: string): { magnitude?: number } | null {
  // Detect `<flag>=<0|-1|unlimited>` or `<flag> <0|-1|unlimited>`.
  const flag = rule.key;
  const lower = rawLine.toLowerCase();
  let searchFrom = 0;
  while (searchFrom < lower.length) {
    const idx = lower.indexOf(flag, searchFrom);
    if (idx < 0) return null;
    const bound = idx === 0 ? "" : lower.charAt(idx - 1);
    if (bound !== "" && bound !== " " && bound !== "\t" && bound !== "\"") {
      searchFrom = idx + flag.length;
      continue;
    }
    const after = rawLine.slice(idx + flag.length);
    const value = readFlagValue(after);
    if (value !== null) {
      const v = stripQuotesTrim(value).toLowerCase();
      if (Object.prototype.hasOwnProperty.call(UNLIMITED_SENTINELS, v)) return {};
      if (v === "0") return {};
    }
    searchFrom = idx + flag.length;
  }
  return null;
}

// ─── KV extraction ─────────────────────────────────────────────────────────

function extractKvValue(rawLine: string, key: string): string | null {
  const lowerLine = rawLine.toLowerCase();
  const lowerKey = key.toLowerCase();
  let idx = 0;
  while (idx < lowerLine.length) {
    const found = lowerLine.indexOf(lowerKey, idx);
    if (found < 0) return null;
    const before = found === 0 ? "" : lowerLine.charAt(found - 1);
    if (!isKeyLeftBoundary(before)) {
      idx = found + 1;
      continue;
    }
    const afterKey = found + lowerKey.length;
    // Skip whitespace then expect ':' or '='.
    let p = afterKey;
    while (p < lowerLine.length && (lowerLine.charAt(p) === " " || lowerLine.charAt(p) === "\t")) p++;
    if (p >= lowerLine.length) return null;
    const sep = lowerLine.charAt(p);
    if (sep !== ":" && sep !== "=") {
      idx = found + 1;
      continue;
    }
    p++;
    while (p < lowerLine.length && (lowerLine.charAt(p) === " " || lowerLine.charAt(p) === "\t" || lowerLine.charAt(p) === '"' || lowerLine.charAt(p) === "'")) p++;
    let end = p;
    while (end < rawLine.length && !isValueRightBoundary(rawLine.charAt(end))) end++;
    return rawLine.slice(p, end).trim();
  }
  return null;
}

function readFlagValue(rest: string): string | null {
  let i = 0;
  while (i < rest.length && (rest.charAt(i) === "=" || rest.charAt(i) === " " || rest.charAt(i) === "\t" || rest.charAt(i) === "\"" || rest.charAt(i) === "'")) i++;
  if (i >= rest.length) return null;
  let end = i;
  while (end < rest.length && !isValueRightBoundary(rest.charAt(end))) end++;
  return rest.slice(i, end);
}

function isKeyLeftBoundary(ch: string): boolean {
  return ch === "" || ch === " " || ch === "\t" || ch === "-" || ch === "{" || ch === "\"" || ch === "'";
}

function isValueRightBoundary(ch: string): boolean {
  return ch === " " || ch === "\t" || ch === "," || ch === "\"" || ch === "'" || ch === "]" || ch === "}" || ch === "#" || ch === "\n";
}

function stripQuotesTrim(s: string): string {
  let r = s.trim();
  if (r.length >= 2) {
    const first = r.charAt(0);
    const last = r.charAt(r.length - 1);
    if ((first === '"' && last === '"') || (first === "'" && last === "'")) {
      r = r.slice(1, r.length - 1);
    }
  }
  return r.trim();
}

function splitNumberUnit(value: string): { number: number | null; unit: string } {
  let i = 0;
  // Optional leading sign.
  if (i < value.length && (value.charAt(i) === "+" || value.charAt(i) === "-")) i++;
  let num = "";
  while (i < value.length) {
    const ch = value.charAt(i);
    if ((ch >= "0" && ch <= "9") || ch === ".") {
      num += ch;
      i++;
    } else {
      break;
    }
  }
  if (num.length === 0) return { number: null, unit: "" };
  const unit = value.slice(i).trim();
  const parsed = parseFloat(num);
  return { number: Number.isFinite(parsed) ? parsed : null, unit };
}

export { MEMORY_UNITS };
