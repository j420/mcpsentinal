/**
 * P5 evidence gathering — Dockerfile build-layer secret detection.
 *
 * No regex literals. Parses Dockerfile directives line-by-line and
 * applies credential-vocabulary lookup + BuildKit-secret exemption.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  CREDENTIAL_TOKENS,
  CREDENTIAL_FILE_BASENAMES,
  BUILDKIT_SECRET_TOKENS,
  type CredentialToken,
} from "./data/credential-tokens.js";

export type P5Variant = "arg" | "env" | "copy-file" | "run-inline";

export interface P5Hit {
  variant: P5Variant;
  file: string;
  line: number;
  observed: string;
  location: Location;
  configLocation: Location;
  /** Which credential token matched (name). */
  credentialName: string;
  credentialKind: string;
  weight: number;
  buildkitSecretNearby: boolean;
}

export interface P5Gathered {
  hits: P5Hit[];
  scannedFiles: string[];
}

export function gatherP5(context: AnalysisContext): P5Gathered {
  const hits: P5Hit[] = [];
  const scannedFiles: string[] = [];

  const files = collectCandidateFiles(context);
  for (const [file, text] of files) {
    scannedFiles.push(file);
    const lines = text.split("\n");
    const buildkitUsedInFile = detectBuildkitUsage(text);
    scanLines(file, lines, buildkitUsedInFile, hits);
  }

  return { hits, scannedFiles };
}

function scanLines(
  file: string,
  lines: string[],
  buildkitUsedInFile: boolean,
  hits: P5Hit[],
): void {
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.trim();
    if (trimmed.length === 0) continue;
    if (trimmed.startsWith("#")) continue;

    // Skip lines that are themselves BuildKit secret mounts (charter
    // lethal edge case #4).
    if (lineUsesBuildkitSecret(raw)) continue;

    const directive = parseDirective(trimmed);
    if (!directive) continue;

    switch (directive.name) {
      case "ARG":
      case "ENV": {
        const token = findCredentialToken(directive.rest);
        if (!token) continue;
        hits.push(
          makeHit(
            directive.name === "ARG" ? "arg" : "env",
            file,
            i,
            trimmed,
            token,
            buildkitUsedInFile,
          ),
        );
        break;
      }
      case "COPY":
      case "ADD": {
        const basename = findCredentialBasename(directive.rest);
        if (!basename) continue;
        hits.push(
          makeHitForFile(directive.name === "COPY" ? "copy-file" : "copy-file", file, i, trimmed, basename, buildkitUsedInFile),
        );
        break;
      }
      case "RUN": {
        // Inline credential assignment — `RUN SECRET=... command`.
        const token = findInlineAssignment(directive.rest);
        if (!token) continue;
        hits.push(
          makeHit("run-inline", file, i, trimmed, token, buildkitUsedInFile),
        );
        break;
      }
    }
  }
}

// ─── Dockerfile directive parsing ──────────────────────────────────────────

interface ParsedDirective {
  name: "ARG" | "ENV" | "COPY" | "ADD" | "RUN";
  rest: string;
}

function parseDirective(trimmed: string): ParsedDirective | null {
  // Split at first whitespace.
  let spaceIdx = -1;
  for (let i = 0; i < trimmed.length; i++) {
    if (trimmed.charAt(i) === " " || trimmed.charAt(i) === "\t") {
      spaceIdx = i;
      break;
    }
  }
  if (spaceIdx < 0) return null;
  const head = trimmed.slice(0, spaceIdx).toUpperCase();
  const rest = trimmed.slice(spaceIdx + 1).trim();
  if (head === "ARG" || head === "ENV" || head === "COPY" || head === "ADD" || head === "RUN") {
    return { name: head, rest };
  }
  return null;
}

// ─── Credential-token matching ─────────────────────────────────────────────

function findCredentialToken(rest: string): CredentialToken | null {
  const upper = rest.toUpperCase();
  for (const [name, tok] of Object.entries(CREDENTIAL_TOKENS)) {
    if (containsToken(upper, name)) return tok;
  }
  return null;
}

function findInlineAssignment(rest: string): CredentialToken | null {
  // RUN <VAR>=<value> <command>... — scan for credential-token VARs.
  const upper = rest.toUpperCase();
  for (const [name, tok] of Object.entries(CREDENTIAL_TOKENS)) {
    const idx = upper.indexOf(name);
    if (idx < 0) continue;
    // Immediate next char must be '=' to be an assignment.
    const rightIdx = idx + name.length;
    if (rightIdx >= upper.length) continue;
    if (upper.charAt(rightIdx) !== "=") continue;
    const leftCh = idx === 0 ? "" : upper.charAt(idx - 1);
    if (!isTokenBoundary(leftCh)) continue;
    return tok;
  }
  return null;
}

function findCredentialBasename(rest: string): string | null {
  const lower = rest.toLowerCase();
  for (const name of Object.keys(CREDENTIAL_FILE_BASENAMES)) {
    if (containsToken(lower, name.toLowerCase())) return name;
  }
  return null;
}

function containsToken(haystack: string, needle: string): boolean {
  let idx = 0;
  while (idx < haystack.length) {
    const found = haystack.indexOf(needle, idx);
    if (found < 0) return false;
    const left = found === 0 ? "" : haystack.charAt(found - 1);
    const right = found + needle.length >= haystack.length ? "" : haystack.charAt(found + needle.length);
    if (isTokenBoundary(left) && isTokenBoundary(right)) return true;
    idx = found + needle.length;
  }
  return false;
}

function isTokenBoundary(ch: string): boolean {
  if (ch === "") return true;
  if (ch === " " || ch === "\t" || ch === "\n") return true;
  if (ch === "=" || ch === ":" || ch === ",") return true;
  if (ch === "\"" || ch === "'") return true;
  if (ch === "/") return true;
  return false;
}

// ─── BuildKit usage detection ──────────────────────────────────────────────

function detectBuildkitUsage(text: string): boolean {
  for (const token of Object.keys(BUILDKIT_SECRET_TOKENS)) {
    if (text.includes(token)) return true;
  }
  return false;
}

function lineUsesBuildkitSecret(rawLine: string): boolean {
  for (const token of Object.keys(BUILDKIT_SECRET_TOKENS)) {
    if (rawLine.includes(token)) return true;
  }
  return false;
}

// ─── Hit construction ──────────────────────────────────────────────────────

function makeHit(
  variant: P5Variant,
  file: string,
  lineIdx: number,
  trimmed: string,
  token: CredentialToken,
  buildkitUsedInFile: boolean,
): P5Hit {
  const lineNumber = lineIdx + 1;
  return {
    variant,
    file,
    line: lineNumber,
    observed: trimmed.length > 180 ? `${trimmed.slice(0, 177)}...` : trimmed,
    location: { kind: "source", file, line: lineNumber, col: 1 },
    configLocation: {
      kind: "config",
      file,
      json_pointer: `/docker/${variant}/${token.name}`,
    },
    credentialName: token.name,
    credentialKind: token.kind,
    weight: token.weight,
    buildkitSecretNearby: buildkitUsedInFile,
  };
}

function makeHitForFile(
  variant: P5Variant,
  file: string,
  lineIdx: number,
  trimmed: string,
  basename: string,
  buildkitUsedInFile: boolean,
): P5Hit {
  const lineNumber = lineIdx + 1;
  const spec = CREDENTIAL_FILE_BASENAMES[basename];
  return {
    variant,
    file,
    line: lineNumber,
    observed: trimmed.length > 180 ? `${trimmed.slice(0, 177)}...` : trimmed,
    location: { kind: "source", file, line: lineNumber, col: 1 },
    configLocation: {
      kind: "config",
      file,
      json_pointer: `/docker/copy/${basename}`,
    },
    credentialName: basename,
    credentialKind: spec?.description ?? basename,
    weight: 0.9,
    buildkitSecretNearby: buildkitUsedInFile,
  };
}

// ─── Candidate file discovery ──────────────────────────────────────────────

function collectCandidateFiles(context: AnalysisContext): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  if (context.source_files && context.source_files.size > 0) {
    for (const [path, text] of context.source_files) {
      if (isDockerfilePath(path)) out.push([path, text]);
    }
    if (out.length > 0) return out;
  }
  if (context.source_code) out.push(["<concatenated-source>", context.source_code]);
  return out;
}

function isDockerfilePath(path: string): boolean {
  const lastSlash = Math.max(path.lastIndexOf("/"), path.lastIndexOf("\\"));
  const basename = lastSlash >= 0 ? path.slice(lastSlash + 1) : path;
  const lower = basename.toLowerCase();
  if (lower === "dockerfile") return true;
  if (lower.startsWith("dockerfile.")) return true;
  if (lower.endsWith(".dockerfile")) return true;
  return false;
}
