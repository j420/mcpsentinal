/**
 * P7 evidence gathering — sensitive host-path detection in volume /
 * mount / hostPath contexts.
 *
 * No regex literals. Path registry lives in ./data/host-paths.ts.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  SENSITIVE_PATHS,
  MOUNT_CONTEXT_TOKENS,
  type SensitivePath,
} from "./data/host-paths.js";

export interface P7Hit {
  spec: SensitivePath;
  file: string;
  line: number;
  observed: string;
  location: Location;
  configLocation: Location;
  /** Whether this mount is read-only per :ro / readOnly: true. */
  readonlyFlag: boolean;
  /** Which mount-context token triggered the detection. */
  mountContext: string;
}

export interface P7Gathered {
  hits: P7Hit[];
  scannedFiles: string[];
}

const CONTEXT_WINDOW = 3;

export function gatherP7(context: AnalysisContext): P7Gathered {
  const hits: P7Hit[] = [];
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
  hits: P7Hit[],
  emittedKeys: Set<string>,
): void {
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.trim();
    if (trimmed.length === 0) continue;
    if (trimmed.startsWith("#") || trimmed.startsWith("//")) continue;

    const windowText = buildContextWindow(lines, i);
    const mountContext = detectMountContext(raw, windowText);
    if (!mountContext) continue;

    // The line must reference the HOST side of a mount — not a
    // container-side destination. Reject `mountPath: /etc/mcp` (k8s
    // volumeMounts), accept `path: /etc` (k8s hostPath block) and
    // short-form `- /etc:/host-etc`.
    if (!lineIsHostSide(raw, windowText)) continue;

    for (const spec of Object.values(SENSITIVE_PATHS)) {
      if (!lineMentionsHostPath(raw, spec)) continue;
      const key = `${file}:${spec.id}:${i}`;
      if (emittedKeys.has(key)) continue;
      emittedKeys.add(key);
      hits.push({
        spec,
        file,
        line: i + 1,
        observed: capObserved(trimmed),
        location: { kind: "source", file, line: i + 1, col: 1 },
        configLocation: {
          kind: "config",
          file,
          json_pointer: `/volumes/${spec.id}`,
        },
        readonlyFlag: detectReadonly(lines, i),
        mountContext,
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
  return lines.slice(start, i + 1).join("\n");
}

function detectMountContext(line: string, windowText: string): string | null {
  const lineLower = line.toLowerCase();
  const windowLower = windowText.toLowerCase();
  for (const token of Object.keys(MOUNT_CONTEXT_TOKENS)) {
    if (lineLower.includes(token)) return token;
    if (windowLower.includes(token)) return token;
  }
  // Short-form volume line: `- /path:/path`.
  if (lineLower.trim().startsWith("-") && lineLower.includes(":")) return "volumes";
  return null;
}

/**
 * Returns true when the path on the line is the HOST side of a mount,
 * not the container destination. Enforced by rejecting `mountPath:`
 * (k8s) and `target:` (compose long-form) keys explicitly.
 */
function lineIsHostSide(rawLine: string, windowText: string): boolean {
  const trimmed = rawLine.trim();
  const lower = rawLine.toLowerCase();
  const windowLower = windowText.toLowerCase();

  // Reject container-destination keys.
  if (trimmed.toLowerCase().startsWith("mountpath")) return false;
  if (trimmed.toLowerCase().startsWith("target:")) return false;

  // Accept explicit host-path keys.
  if (trimmed.toLowerCase().startsWith("path:")) {
    // Confirm we're under a hostPath window.
    if (windowLower.includes("hostpath")) return true;
    return false;
  }
  if (trimmed.toLowerCase().startsWith("source:")) return true;
  if (trimmed.toLowerCase().startsWith("hostpath:")) return true;

  // Short-form volumes: `- /host:/container[:ro]` — the host path is
  // before the first ':' on the line.
  if (trimmed.startsWith("-")) {
    const afterDash = trimmed.slice(1).trimStart();
    if (afterDash.startsWith("/") || afterDash.startsWith("~") || afterDash.startsWith("\"/") || afterDash.startsWith("'/")) {
      return true;
    }
  }

  // Docker CLI: --volume / -v / --mount source=...
  if (lower.includes("--volume") || lower.includes("--mount") || (lower.includes(" -v ") && lower.includes(":"))) {
    return true;
  }

  return false;
}

function detectReadonly(lines: string[], i: number): boolean {
  const lo = (lines[i] ?? "").toLowerCase();
  const before = (lines[i - 1] ?? "").toLowerCase();
  const after = (lines[i + 1] ?? "").toLowerCase();
  const window = `${before}\n${lo}\n${after}`;
  if (window.includes(":ro")) return true;
  if (window.includes("readonly: true")) return true;
  if (window.includes("readonly:true")) return true;
  if (window.includes("read_only: true")) return true;
  return false;
}

// ─── Path-prefix matching ──────────────────────────────────────────────────

function lineMentionsHostPath(rawLine: string, spec: SensitivePath): boolean {
  // Special-case: SSH key directory matches both /root/.ssh and ~/.ssh /home/...
  if (spec.id === "host-ssh-keys") {
    if (lineHasSshPath(rawLine)) return true;
    return false;
  }
  if (spec.id === "host-kube-config") {
    if (lineHasKubeConfigPath(rawLine)) return true;
    return false;
  }
  // Special-case: root. Match only the exact values "/" or "/:" shapes.
  if (spec.isRootFilesystem) {
    return lineHasRootMount(rawLine);
  }
  return lineHasPrefix(rawLine, spec.path);
}

function lineHasPrefix(rawLine: string, prefix: string): boolean {
  const idx = rawLine.indexOf(prefix);
  if (idx < 0) return false;
  const left = idx === 0 ? "" : rawLine.charAt(idx - 1);
  if (!isPathBoundary(left)) return false;
  const rightIdx = idx + prefix.length;
  // A prefix match is valid only when the next char is a path
  // continuation (/ or :) or a path terminator (space, quote, comma).
  if (rightIdx >= rawLine.length) return true;
  const right = rawLine.charAt(rightIdx);
  if (right === "/" || right === ":" || right === " " || right === "\t") return true;
  if (right === "\"" || right === "'" || right === ",") return true;
  return false;
}

function lineHasSshPath(rawLine: string): boolean {
  // Match /.ssh as a path fragment — also catches /root/.ssh and /home/user/.ssh.
  return lineHasPrefix(rawLine, "/.ssh") || rawLine.includes(".ssh");
}

function lineHasKubeConfigPath(rawLine: string): boolean {
  return lineHasPrefix(rawLine, "/.kube") || rawLine.includes(".kube");
}

function lineHasRootMount(rawLine: string): boolean {
  // Root-filesystem mount shapes:
  //   `hostPath: /` / `hostPath: "/"` / `path: /`
  //   `- /:/` short-form
  //   `--volume /:/host`
  // Require an explicit "/" value whose right side is a separator, not `/etc/` etc.
  // Scan for unattached `/` as a value.
  for (let i = 0; i < rawLine.length; i++) {
    const ch = rawLine.charAt(i);
    if (ch !== "/") continue;
    const left = i === 0 ? "" : rawLine.charAt(i - 1);
    const right = i + 1 >= rawLine.length ? "" : rawLine.charAt(i + 1);
    // Needs a left boundary indicating "this is a value".
    if (!isRootLeftBoundary(left)) continue;
    // Needs an end / next-token boundary — not another path char.
    if (right === "" || right === " " || right === "\t" || right === "\"" || right === "'" || right === ":" || right === "," || right === "\n") {
      return true;
    }
  }
  return false;
}

function isRootLeftBoundary(ch: string): boolean {
  if (ch === "") return true;
  if (ch === " " || ch === "\t" || ch === ":") return true;
  if (ch === "\"" || ch === "'") return true;
  if (ch === "=") return true;
  return false;
}

function isPathBoundary(ch: string): boolean {
  if (ch === "") return true;
  if (ch === " " || ch === "\t" || ch === "\n") return true;
  if (ch === "\"" || ch === "'") return true;
  if (ch === ":" || ch === ",") return true;
  if (ch === "[" || ch === "]" || ch === "{" || ch === "}") return true;
  return false;
}
