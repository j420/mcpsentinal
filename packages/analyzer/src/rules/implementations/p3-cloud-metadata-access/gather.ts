/**
 * P3 evidence gathering — cloud metadata endpoint detection.
 *
 * No regex literals. All endpoint vocabulary lives in ./data/endpoints.ts.
 * Matches are whole-token (boundary-aware) and are suppressed when the
 * same line contains a block / deny / reject token.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  METADATA_ENDPOINTS,
  BLOCK_CONTEXT_TOKENS,
  HOP_LIMIT_TOKEN,
  type EndpointSpec,
} from "./data/endpoints.js";

export type P3Variant = "endpoint" | "hop-limit";

export interface P3EndpointHit {
  kind: "endpoint";
  spec: EndpointSpec;
  file: string;
  line: number;
  observed: string;
  location: Location;
  configLocation: Location;
}

export interface P3HopLimitHit {
  kind: "hop-limit";
  file: string;
  line: number;
  value: number;
  observed: string;
  location: Location;
  configLocation: Location;
}

export type P3Hit = P3EndpointHit | P3HopLimitHit;

export interface P3Gathered {
  hits: P3Hit[];
  scannedFiles: string[];
}

export function gatherP3(context: AnalysisContext): P3Gathered {
  const hits: P3Hit[] = [];
  const scannedFiles: string[] = [];

  const files = collectCandidateFiles(context);
  for (const [file, text] of files) {
    scannedFiles.push(file);
    const lines = text.split("\n");
    scanLines(file, lines, hits);
  }

  return { hits, scannedFiles };
}

function scanLines(file: string, lines: string[], hits: P3Hit[]): void {
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.trim();
    if (trimmed.length === 0) continue;
    if (trimmed.startsWith("#") || trimmed.startsWith("//")) continue;

    const blockContext = detectBlockContext(buildBlockContextWindow(lines, i));

    for (const spec of Object.values(METADATA_ENDPOINTS)) {
      if (!lineReferencesEndpoint(raw, spec)) continue;
      if (blockContext) continue;
      hits.push({
        kind: "endpoint",
        spec,
        file,
        line: i + 1,
        observed: capObserved(trimmed),
        location: { kind: "source", file, line: i + 1, col: 1 },
        configLocation: {
          kind: "config",
          file,
          json_pointer: `/metadata/${spec.id}`,
        },
      });
    }

    // Lethal edge #5 — IMDSv2 hop limit inflation.
    const hopValue = extractHopLimitValue(raw);
    if (hopValue !== null && hopValue >= 2) {
      hits.push({
        kind: "hop-limit",
        file,
        line: i + 1,
        value: hopValue,
        observed: capObserved(trimmed),
        location: { kind: "source", file, line: i + 1, col: 1 },
        configLocation: {
          kind: "config",
          file,
          json_pointer: "/metadata/HttpPutResponseHopLimit",
        },
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
      if (isCandidatePath(path)) out.push([path, text]);
    }
    if (out.length > 0) return out;
  }
  if (context.source_code) out.push(["<concatenated-source>", context.source_code]);
  return out;
}

function isCandidatePath(path: string): boolean {
  const lower = path.toLowerCase();
  // Source code and infrastructure-as-code.
  if (lower.endsWith(".ts") || lower.endsWith(".tsx") || lower.endsWith(".js") || lower.endsWith(".jsx")) return true;
  if (lower.endsWith(".mts") || lower.endsWith(".cts") || lower.endsWith(".mjs") || lower.endsWith(".cjs")) return true;
  if (lower.endsWith(".py")) return true;
  if (lower.endsWith(".go") || lower.endsWith(".rs") || lower.endsWith(".java")) return true;
  if (lower.endsWith(".yaml") || lower.endsWith(".yml")) return true;
  if (lower.endsWith(".tf") || lower.endsWith(".tf.json")) return true;
  if (lower.endsWith(".json")) return true;
  if (lower.endsWith(".sh")) return true;
  return false;
}

// ─── Endpoint matching ─────────────────────────────────────────────────────

function lineReferencesEndpoint(rawLine: string, spec: EndpointSpec): boolean {
  const haystack =
    spec.family === "ipv4" || spec.family === "ipv6" ? rawLine : rawLine.toLowerCase();
  const needle =
    spec.family === "ipv4" || spec.family === "ipv6" ? spec.token : spec.token.toLowerCase();
  let idx = 0;
  while (idx < haystack.length) {
    const found = haystack.indexOf(needle, idx);
    if (found < 0) return false;
    const left = found === 0 ? "" : haystack.charAt(found - 1);
    const rightIdx = found + needle.length;
    const right = rightIdx >= haystack.length ? "" : haystack.charAt(rightIdx);
    if (isEndpointBoundary(left) && isEndpointBoundary(right)) return true;
    idx = found + needle.length;
  }
  return false;
}

function isEndpointBoundary(ch: string): boolean {
  if (ch === "") return true;
  if (ch === " " || ch === "\t" || ch === "\n") return true;
  if (ch === "\"" || ch === "'" || ch === "`") return true;
  if (ch === "/" || ch === ":" || ch === ",") return true;
  if (ch === "(" || ch === ")" || ch === "[" || ch === "]" || ch === "{" || ch === "}") return true;
  if (ch === "=") return true;
  return false;
}

function detectBlockContext(windowText: string): string | null {
  const lower = windowText.toLowerCase();
  for (const token of Object.keys(BLOCK_CONTEXT_TOKENS)) {
    if (lower.includes(token)) return token;
  }
  // NetworkPolicy pattern: `except:` indicates an egress-allow with specific
  // deny entries. Treat except-block entries as defensive references.
  if (lower.includes("except:") || lower.includes("except ")) return "except";
  return null;
}

function buildBlockContextWindow(lines: string[], i: number): string {
  const start = Math.max(0, i - 4);
  const end = Math.min(lines.length, i + 2);
  return lines.slice(start, end).join("\n");
}

// ─── Hop-limit extraction ─────────────────────────────────────────────────

function extractHopLimitValue(rawLine: string): number | null {
  const lower = rawLine.toLowerCase();
  const tokenLower = HOP_LIMIT_TOKEN.toLowerCase();
  const idx = lower.indexOf(tokenLower);
  if (idx < 0) return null;
  const afterKey = idx + tokenLower.length;
  let p = afterKey;
  while (p < rawLine.length && (rawLine.charAt(p) === " " || rawLine.charAt(p) === "\t")) p++;
  if (p >= rawLine.length) return null;
  const sep = rawLine.charAt(p);
  if (sep !== ":" && sep !== "=") return null;
  p++;
  while (p < rawLine.length && (rawLine.charAt(p) === " " || rawLine.charAt(p) === "\t" || rawLine.charAt(p) === "\"" || rawLine.charAt(p) === "'")) p++;
  let num = "";
  while (p < rawLine.length) {
    const ch = rawLine.charAt(p);
    if (ch >= "0" && ch <= "9") {
      num += ch;
      p++;
    } else {
      break;
    }
  }
  if (num.length === 0) return null;
  const v = parseInt(num, 10);
  return Number.isFinite(v) ? v : null;
}
