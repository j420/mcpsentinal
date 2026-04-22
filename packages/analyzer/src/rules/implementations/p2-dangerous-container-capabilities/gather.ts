/**
 * P2 evidence gathering — dangerous capability / privileged-mode /
 * host-namespace detection across compose, k8s, Dockerfile, and shell.
 *
 * No regex literals. All vocabularies live in ./data/capabilities.ts.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  DANGEROUS_CAPABILITIES,
  NAMESPACE_TRIGGERS,
  CAPABILITY_CONTEXT_TOKENS,
  type CapabilitySpec,
  type NamespaceSpec,
} from "./data/capabilities.js";

export type P2HitKind = "capability" | "namespace";

export interface P2CapabilityHit {
  kind: "capability";
  spec: CapabilitySpec;
  file: string;
  line: number;
  observed: string;
  location: Location;
  configLocation: Location;
  context: string;
  dropAllCompanion: boolean;
}

export interface P2NamespaceHit {
  kind: "namespace";
  spec: NamespaceSpec;
  file: string;
  line: number;
  observed: string;
  location: Location;
  configLocation: Location;
}

export type P2Hit = P2CapabilityHit | P2NamespaceHit;

export interface P2Gathered {
  hits: P2Hit[];
  scannedFiles: string[];
}

const CONTEXT_WINDOW = 4;

export function gatherP2(context: AnalysisContext): P2Gathered {
  const hits: P2Hit[] = [];
  const scannedFiles: string[] = [];

  const files = collectCandidateFiles(context);
  for (const [file, text] of files) {
    scannedFiles.push(file);
    const lines = text.split("\n");
    const emittedKeys = new Set<string>();
    scanLines(file, lines, hits, emittedKeys);
  }

  return { hits, scannedFiles };
}

function scanLines(
  file: string,
  lines: string[],
  hits: P2Hit[],
  emittedKeys: Set<string>,
): void {
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.trim();
    if (trimmed.length === 0) continue;
    if (trimmed.startsWith("#") || trimmed.startsWith("//")) continue;

    // Namespace triggers (privileged / hostPID / hostIPC / hostNetwork / hostUsers).
    for (const spec of Object.values(NAMESPACE_TRIGGERS)) {
      if (matchNamespaceTrigger(raw, spec)) {
        const key = `ns:${file}:${spec.id}:${i}`;
        if (emittedKeys.has(key)) continue;
        emittedKeys.add(key);
        hits.push({
          kind: "namespace",
          spec,
          file,
          line: i + 1,
          observed: capObserved(trimmed),
          location: { kind: "source", file, line: i + 1, col: 1 },
          configLocation: {
            kind: "config",
            file,
            json_pointer: `/securityContext/${spec.id}`,
          },
        });
      }
    }

    // Capability adds — but only when the nearest add/drop block is "add".
    const windowText = buildContextWindow(lines, i);
    const ctx = detectCapabilityContext(windowText);
    if (!ctx) continue;
    const addBlock = lineIsUnderAddBlock(lines, i);
    if (!addBlock) continue;
    const dropAll = windowContainsDropAll(windowText);

    for (const spec of Object.values(DANGEROUS_CAPABILITIES)) {
      if (!lineReferencesCapability(raw, spec.name)) continue;
      const key = `cap:${file}:${spec.name.toLowerCase()}:${i}`;
      if (emittedKeys.has(key)) continue;
      emittedKeys.add(key);
      hits.push({
        kind: "capability",
        spec,
        file,
        line: i + 1,
        observed: capObserved(trimmed),
        location: { kind: "source", file, line: i + 1, col: 1 },
        configLocation: {
          kind: "config",
          file,
          json_pointer: `/securityContext/capabilities/add/${spec.name.toLowerCase()}`,
        },
        context: ctx,
        dropAllCompanion: dropAll,
      });
    }
  }
}

function capObserved(line: string): string {
  return line.length > 180 ? `${line.slice(0, 177)}...` : line;
}

// ─── Candidate file discovery ──────────────────────────────────────────────

function collectCandidateFiles(context: AnalysisContext): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  if (context.source_files && context.source_files.size > 0) {
    for (const [path, text] of context.source_files) {
      if (isRuntimeConfigPath(path)) out.push([path, text]);
    }
    if (out.length > 0) return out;
  }
  if (context.source_code) out.push(["<concatenated-source>", context.source_code]);
  return out;
}

function isRuntimeConfigPath(path: string): boolean {
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

// ─── Context detection ─────────────────────────────────────────────────────

function buildContextWindow(lines: string[], i: number): string {
  const start = Math.max(0, i - CONTEXT_WINDOW);
  const end = Math.min(lines.length, i + 2);
  return lines.slice(start, end).join("\n");
}

function detectCapabilityContext(windowText: string): string | null {
  const lower = windowText.toLowerCase();
  for (const token of Object.keys(CAPABILITY_CONTEXT_TOKENS)) {
    if (lower.includes(token)) return token;
  }
  return null;
}

function windowContainsDropAll(windowText: string): boolean {
  const lower = windowText.toLowerCase();
  if (lower.includes("drop")) {
    // Look for ALL within the window near a drop marker.
    if (lower.includes("all")) return true;
  }
  return false;
}

/**
 * Walk backward through the preceding lines looking for the nearest
 * add-ish marker. Returns true when the nearest parent marker indicates
 * the capability at `lineIdx` is being ADDED (not DROPPED).
 *
 * Recognised add markers:
 *   `add:`                — k8s securityContext.capabilities.add list
 *   `cap_add:`            — docker-compose service.cap_add
 *   `--cap-add`           — docker CLI flag on the same or preceding line
 *
 * Recognised drop markers:
 *   `drop:`               — k8s capabilities.drop list
 *   `cap_drop:`           — docker-compose service.cap_drop
 *   `--cap-drop`          — docker CLI flag
 */
function lineIsUnderAddBlock(lines: string[], lineIdx: number): boolean {
  for (let j = lineIdx; j >= Math.max(0, lineIdx - CONTEXT_WINDOW - 2); j--) {
    const lower = (lines[j] ?? "").toLowerCase();
    if (lower.includes("cap_drop") || lower.includes("--cap-drop")) return false;
    if (lower.includes("cap_add") || lower.includes("--cap-add")) return true;
    const trimmed = lower.trim();
    if (trimmed.startsWith("drop:") || trimmed === "drop:") return false;
    if (trimmed.startsWith("add:") || trimmed === "add:") return true;
  }
  return false;
}

// ─── Namespace trigger matching ────────────────────────────────────────────

function matchNamespaceTrigger(rawLine: string, spec: NamespaceSpec): boolean {
  const value = extractKvValue(rawLine, spec.key, isCamelCaseKey(spec.key));
  if (value === null) return false;
  const lower = stripQuotesTrim(value).toLowerCase();
  return Object.prototype.hasOwnProperty.call(spec.triggerValues, lower);
}

function isCamelCaseKey(key: string): boolean {
  // hostPID, hostIPC, hostNetwork, hostUsers — kubernetes camel-case,
  // match case-sensitively to avoid YAML keys that happen to share lowercase
  // prefixes. privileged is lowercase universally.
  return key.startsWith("host");
}

// ─── Capability line matching ──────────────────────────────────────────────

function lineReferencesCapability(rawLine: string, capName: string): boolean {
  const lower = rawLine.toLowerCase();
  const lowerCap = capName.toLowerCase();
  const withPrefix = `cap_${lowerCap}`;
  return (
    hasTokenBoundary(lower, lowerCap) ||
    hasTokenBoundary(lower, withPrefix)
  );
}

function hasTokenBoundary(haystack: string, needle: string): boolean {
  let idx = 0;
  while (idx < haystack.length) {
    const found = haystack.indexOf(needle, idx);
    if (found < 0) return false;
    const left = found === 0 ? "" : haystack.charAt(found - 1);
    const rightIdx = found + needle.length;
    const right = rightIdx >= haystack.length ? "" : haystack.charAt(rightIdx);
    if (isTokenBoundary(left) && isTokenBoundary(right)) return true;
    idx = found + needle.length;
  }
  return false;
}

function isTokenBoundary(ch: string): boolean {
  if (ch === "") return true;
  if (ch === " " || ch === "\t" || ch === "\n") return true;
  if (ch === ":" || ch === "=" || ch === ",") return true;
  if (ch === "\"" || ch === "'" || ch === "[" || ch === "]" || ch === "{" || ch === "}") return true;
  if (ch === "-") return true;
  return false;
}

// ─── KV extraction (shared pattern with sibling P9/P10) ───────────────────

function extractKvValue(rawLine: string, key: string, caseSensitiveKey: boolean): string | null {
  const haystack = caseSensitiveKey ? rawLine : rawLine.toLowerCase();
  const needle = caseSensitiveKey ? key : key.toLowerCase();
  let idx = 0;
  while (idx < haystack.length) {
    const found = haystack.indexOf(needle, idx);
    if (found < 0) return null;
    const before = found === 0 ? "" : haystack.charAt(found - 1);
    if (!isKeyLeftBoundary(before)) {
      idx = found + 1;
      continue;
    }
    const afterKey = found + needle.length;
    let p = afterKey;
    while (p < haystack.length && (haystack.charAt(p) === " " || haystack.charAt(p) === "\t")) p++;
    if (p >= haystack.length) return null;
    const sep = haystack.charAt(p);
    if (sep !== ":" && sep !== "=") {
      idx = found + 1;
      continue;
    }
    p++;
    while (p < rawLine.length && (rawLine.charAt(p) === " " || rawLine.charAt(p) === "\t" || rawLine.charAt(p) === "\"" || rawLine.charAt(p) === "'")) p++;
    let end = p;
    while (end < rawLine.length && !isValueRightBoundary(rawLine.charAt(end))) end++;
    return rawLine.slice(p, end);
  }
  return null;
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
    if ((first === "\"" && last === "\"") || (first === "'" && last === "'")) {
      r = r.slice(1, r.length - 1);
    }
  }
  return r.trim();
}
