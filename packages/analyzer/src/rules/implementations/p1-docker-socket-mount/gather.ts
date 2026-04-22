/**
 * P1 evidence gathering — socket-path detection across Dockerfiles,
 * docker-compose YAML, Kubernetes manifests, and shell scripts.
 *
 * No regex literals. All pattern tables live in ./data/socket-paths.ts.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  SOCKET_PATHS,
  SOCKET_BASENAME_FRAGMENTS,
  MOUNT_CONTEXT_TOKENS,
  type SocketPathSpec,
} from "./data/socket-paths.js";

export interface P1Hit {
  spec: SocketPathSpec;
  file: string;
  line: number;
  observed: string;
  /** Source-kind location for the line. */
  location: Location;
  /** Config-kind location with json_pointer for the mount. */
  configLocation: Location;
  /** True when `:ro` or `readOnly: true` appears on or near the mount. */
  readonlyFlag: boolean;
  /** Which mount-context token made this a volume line. */
  mountContext: string;
}

export interface P1Gathered {
  hits: P1Hit[];
  scannedFiles: string[];
}

const CONTEXT_WINDOW = 3;

export function gatherP1(context: AnalysisContext): P1Gathered {
  const hits: P1Hit[] = [];
  const scannedFiles: string[] = [];

  const files = collectCandidateFiles(context);
  for (const [file, text] of files) {
    scannedFiles.push(file);
    const lines = text.split("\n");
    scanLines(file, lines, hits);
  }

  return { hits, scannedFiles };
}

function scanLines(file: string, lines: string[], hits: P1Hit[]): void {
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.trim();
    if (trimmed.length === 0) continue;
    if (trimmed.startsWith("#") || trimmed.startsWith("//")) continue;

    const windowText = buildContextWindow(lines, i);
    const mountContext = detectMountContext(raw, windowText);
    if (!mountContext) continue;

    // Track 1: whole-path match for a known runtime socket.
    for (const spec of Object.values(SOCKET_PATHS)) {
      if (lineContainsToken(raw, spec.path)) {
        hits.push(buildHit(file, lines, i, trimmed, spec, mountContext));
      }
    }

    // Track 2: basename fragment appears on this line combined with a
    // split-path pattern — subPath reconstruction (charter lethal edge
    // case #3). We emit a synthetic hit keyed to the matching runtime's
    // primary socket entry so downstream reporting remains canonical.
    for (const fragment of Object.keys(SOCKET_BASENAME_FRAGMENTS)) {
      if (!lineContainsTokenCI(raw, fragment)) continue;
      // Skip if we already matched the full path above — avoid double-
      // emitting the exact same hit.
      if (Object.values(SOCKET_PATHS).some((s) => lineContainsToken(raw, s.path))) continue;
      const spec = resolveSpecForFragment(fragment);
      if (!spec) continue;
      hits.push(buildHit(file, lines, i, trimmed, spec, mountContext));
    }
  }
}

function buildHit(
  file: string,
  lines: string[],
  lineIdx: number,
  trimmed: string,
  spec: SocketPathSpec,
  mountContext: string,
): P1Hit {
  const lineNumber = lineIdx + 1;
  return {
    spec,
    file,
    line: lineNumber,
    observed: trimmed.length > 180 ? `${trimmed.slice(0, 177)}...` : trimmed,
    location: { kind: "source", file, line: lineNumber, col: 1 },
    configLocation: {
      kind: "config",
      file,
      json_pointer: `/volumes/${spec.id}`,
    },
    readonlyFlag: detectReadonly(lines, lineIdx),
    mountContext,
  };
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

// ─── Mount-context detection ───────────────────────────────────────────────

function buildContextWindow(lines: string[], i: number): string {
  const start = Math.max(0, i - CONTEXT_WINDOW);
  return lines.slice(start, i + 1).join("\n");
}

function detectMountContext(line: string, windowText: string): string | null {
  const lineLower = line.toLowerCase();
  const windowLower = windowText.toLowerCase();
  for (const token of Object.keys(MOUNT_CONTEXT_TOKENS)) {
    if (lineLower.includes(token)) return token;
    if (windowLower.includes(token)) return token;
  }
  // Also treat a compose-style `- /path:/path` short-form as a volume
  // context if the line starts with a dash and contains a colon.
  if (lineLower.trim().startsWith("-") && lineLower.includes(":")) return "volumes";
  return null;
}

function detectReadonly(lines: string[], i: number): boolean {
  const window = [
    lines[i] ?? "",
    lines[i + 1] ?? "",
    lines[i - 1] ?? "",
  ]
    .join("\n")
    .toLowerCase();
  if (window.includes(":ro")) return true;
  if (window.includes("readonly: true")) return true;
  if (window.includes("readonly:true")) return true;
  if (window.includes("read_only: true")) return true;
  return false;
}

// ─── Path / token matching ─────────────────────────────────────────────────

function lineContainsToken(line: string, path: string): boolean {
  const idx = line.indexOf(path);
  if (idx < 0) return false;
  const left = idx === 0 ? "" : line.charAt(idx - 1);
  const rightIdx = idx + path.length;
  const right = rightIdx >= line.length ? "" : line.charAt(rightIdx);
  return isPathBoundary(left) && isPathBoundary(right);
}

function lineContainsTokenCI(line: string, token: string): boolean {
  const lower = line.toLowerCase();
  const needle = token.toLowerCase();
  const idx = lower.indexOf(needle);
  if (idx < 0) return false;
  const left = idx === 0 ? "" : lower.charAt(idx - 1);
  const rightIdx = idx + needle.length;
  const right = rightIdx >= lower.length ? "" : lower.charAt(rightIdx);
  return isPathBoundary(left) && isPathBoundary(right);
}

function isPathBoundary(ch: string): boolean {
  if (ch === "") return true;
  if (ch === " " || ch === "\t" || ch === "\"" || ch === "'" || ch === ":") return true;
  if (ch === "," || ch === "[" || ch === "]" || ch === "{" || ch === "}") return true;
  if (ch === "\n") return true;
  return false;
}

function resolveSpecForFragment(fragment: string): SocketPathSpec | null {
  const fragmentLower = fragment.toLowerCase();
  if (fragmentLower === "docker.sock") return SOCKET_PATHS["docker-var-run"];
  if (fragmentLower === "containerd.sock") return SOCKET_PATHS["containerd-var-run"];
  if (fragmentLower === "crio.sock") return SOCKET_PATHS["crio-var-run"];
  if (fragmentLower === "podman.sock") return SOCKET_PATHS["podman-run"];
  return null;
}
