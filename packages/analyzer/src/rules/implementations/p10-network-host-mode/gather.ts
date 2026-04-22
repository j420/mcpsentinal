/**
 * P10 evidence gathering — line-oriented host-network detection.
 *
 * No regex literals. Patterns live in ./data/host-network-patterns.ts.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  HOST_NETWORK_PATTERNS,
  ISOLATION_ALTERNATIVE_TOKENS,
  type HostNetworkPattern,
} from "./data/host-network-patterns.js";

export interface P10Hit {
  pattern: HostNetworkPattern;
  file: string;
  line: number;
  observed: string;
  location: Location;
  configLocation: Location;
}

export interface P10Gathered {
  hits: P10Hit[];
  /** Per-file alternative-isolation controls that were observed. */
  alternativesPerFile: Map<string, Set<string>>;
  scannedFiles: string[];
}

export function gatherP10(context: AnalysisContext): P10Gathered {
  const hits: P10Hit[] = [];
  const alternativesPerFile = new Map<string, Set<string>>();
  const scannedFiles: string[] = [];

  const files = collectCandidateFiles(context);
  for (const [file, text] of files) {
    scannedFiles.push(file);
    const lines = text.split("\n");
    const alts = new Set<string>();

    for (let i = 0; i < lines.length; i++) {
      const raw = lines[i];
      const trimmed = raw.trim();
      if (trimmed.length === 0) continue;
      if (trimmed.startsWith("#") || trimmed.startsWith("//")) continue;

      // Alternative isolation controls (case-sensitive for K8s NetworkPolicy).
      for (const token of Object.keys(ISOLATION_ALTERNATIVE_TOKENS)) {
        if (containsAlternativeToken(raw, token)) alts.add(token);
      }

      // Match each pattern.
      for (const pattern of Object.values(HOST_NETWORK_PATTERNS)) {
        if (matchesPattern(pattern, raw, trimmed)) {
          hits.push({
            pattern,
            file,
            line: i + 1,
            observed: trimmed.length > 180 ? `${trimmed.slice(0, 177)}...` : trimmed,
            location: { kind: "source", file, line: i + 1, col: 1 },
            configLocation: {
              kind: "config",
              file,
              json_pointer: `/network/${pattern.id}`,
            },
          });
        }
      }
    }

    if (alts.size > 0) alternativesPerFile.set(file, alts);
  }

  return { hits, alternativesPerFile, scannedFiles };
}

// ─── Candidate file discovery ──────────────────────────────────────────────

function collectCandidateFiles(context: AnalysisContext): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  if (context.source_files && context.source_files.size > 0) {
    for (const [path, text] of context.source_files) {
      if (isNetConfigPath(path)) out.push([path, text]);
    }
    if (out.length > 0) return out;
  }
  if (context.source_code) out.push(["<concatenated-source>", context.source_code]);
  return out;
}

function isNetConfigPath(path: string): boolean {
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

// ─── Pattern matching ──────────────────────────────────────────────────────

function matchesPattern(
  pattern: HostNetworkPattern,
  rawLine: string,
  _trimmed: string,
): boolean {
  switch (pattern.matchKind) {
    case "kv-value":
      if (!pattern.trigger) return false;
      return caseSensitiveKvValueMatch(rawLine, pattern.key, pattern.trigger, isKubernetesKey(pattern.key));
    case "kv-true":
      return caseSensitiveKvTrueMatch(rawLine, pattern.key, isKubernetesKey(pattern.key));
    case "cli-flag-eq-host":
      return cliFlagHostMatch(rawLine, pattern.key);
  }
}

function isKubernetesKey(key: string): boolean {
  // Kubernetes API schema uses camelCase: hostNetwork, pidsLimit, networkMode.
  return key === "hostNetwork" || key === "networkMode";
}

/** `key: value` or `key=value` on one line. Returns value lowercase-compared. */
function caseSensitiveKvValueMatch(
  rawLine: string,
  key: string,
  trigger: string,
  caseSensitiveKey: boolean,
): boolean {
  const matchIdx = findKeyStartIndex(rawLine, key, caseSensitiveKey);
  if (matchIdx < 0) return false;
  const afterKey = matchIdx + key.length;
  let p = afterKey;
  while (p < rawLine.length && (rawLine.charAt(p) === " " || rawLine.charAt(p) === "\t")) p++;
  if (p >= rawLine.length) return false;
  const sep = rawLine.charAt(p);
  if (sep !== ":" && sep !== "=") return false;
  p++;
  while (p < rawLine.length && (rawLine.charAt(p) === " " || rawLine.charAt(p) === "\t" || rawLine.charAt(p) === "\"" || rawLine.charAt(p) === "'")) p++;
  let end = p;
  while (end < rawLine.length && !isValueRightBoundary(rawLine.charAt(end))) end++;
  const value = rawLine.slice(p, end).trim().toLowerCase();
  return value === trigger.toLowerCase();
}

function caseSensitiveKvTrueMatch(
  rawLine: string,
  key: string,
  caseSensitiveKey: boolean,
): boolean {
  return (
    caseSensitiveKvValueMatch(rawLine, key, "true", caseSensitiveKey) ||
    caseSensitiveKvValueMatch(rawLine, key, "yes", caseSensitiveKey) ||
    caseSensitiveKvValueMatch(rawLine, key, "1", caseSensitiveKey)
  );
}

function cliFlagHostMatch(rawLine: string, flag: string): boolean {
  // Match `flag=host` or `flag host` (whitespace-separated).
  const lower = rawLine.toLowerCase();
  const lowerFlag = flag.toLowerCase();
  let idx = 0;
  while (idx < lower.length) {
    const found = lower.indexOf(lowerFlag, idx);
    if (found < 0) return false;
    const before = found === 0 ? "" : lower.charAt(found - 1);
    if (before !== "" && before !== " " && before !== "\t" && before !== "\"") {
      idx = found + lowerFlag.length;
      continue;
    }
    const after = rawLine.slice(found + lowerFlag.length);
    const value = readFlagValue(after);
    if (value !== null && value.toLowerCase() === "host") return true;
    idx = found + lowerFlag.length;
  }
  return false;
}

function readFlagValue(rest: string): string | null {
  let i = 0;
  while (i < rest.length && (rest.charAt(i) === "=" || rest.charAt(i) === " " || rest.charAt(i) === "\t" || rest.charAt(i) === "\"" || rest.charAt(i) === "'")) i++;
  if (i >= rest.length) return null;
  let end = i;
  while (end < rest.length && !isValueRightBoundary(rest.charAt(end))) end++;
  return rest.slice(i, end).trim();
}

function findKeyStartIndex(rawLine: string, key: string, caseSensitiveKey: boolean): number {
  const haystack = caseSensitiveKey ? rawLine : rawLine.toLowerCase();
  const needle = caseSensitiveKey ? key : key.toLowerCase();
  let idx = 0;
  while (idx < haystack.length) {
    const found = haystack.indexOf(needle, idx);
    if (found < 0) return -1;
    const before = found === 0 ? "" : haystack.charAt(found - 1);
    if (isKeyLeftBoundary(before)) return found;
    idx = found + 1;
  }
  return -1;
}

function isKeyLeftBoundary(ch: string): boolean {
  return ch === "" || ch === " " || ch === "\t" || ch === "-" || ch === "{" || ch === "\"" || ch === "'";
}

function isValueRightBoundary(ch: string): boolean {
  return ch === " " || ch === "\t" || ch === "," || ch === "\"" || ch === "'" || ch === "]" || ch === "}" || ch === "#" || ch === "\n";
}

// ─── Alternative-token detection ───────────────────────────────────────────

function containsAlternativeToken(rawLine: string, token: string): boolean {
  // Case-sensitive for NetworkPolicy (capitalised in k8s).
  const isCapKey = token === "NetworkPolicy";
  const haystack = isCapKey ? rawLine : rawLine.toLowerCase();
  const needle = isCapKey ? token : token.toLowerCase();
  const found = haystack.indexOf(needle);
  if (found < 0) return false;
  const before = found === 0 ? "" : haystack.charAt(found - 1);
  const after = found + needle.length >= haystack.length ? "" : haystack.charAt(found + needle.length);
  return isAltBoundary(before) && isAltBoundary(after);
}

function isAltBoundary(ch: string): boolean {
  if (ch === "") return true;
  if (ch === " " || ch === "\t" || ch === ":" || ch === "=" || ch === "," || ch === "\n") return true;
  if (ch === "\"" || ch === "'" || ch === "{" || ch === "}" || ch === "[" || ch === "]") return true;
  return false;
}
