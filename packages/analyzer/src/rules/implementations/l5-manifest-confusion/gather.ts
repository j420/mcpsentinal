/**
 * L5 evidence gathering — structural, AST-based.
 *
 * Three data shapes feed this rule:
 *
 *   1. A whole file that IS a package.json (the scan pipeline passes
 *      it through `source_files` when `context.source_files` contains
 *      a "package.json" entry) — parsed via JSON.parse.
 *
 *   2. An object-literal embedded in TypeScript / JavaScript code whose
 *      shape matches a package.json (has a `scripts`, `bin`, or
 *      `exports` top-level key) — parsed via the TypeScript AST.
 *
 *   3. The structural shape exists but the values we care about are
 *      not literal (computed property, variable reference). Those are
 *      skipped — static analysis cannot soundly classify them.
 *
 * The output is a list of L5Primitive records tagged with structural
 * Locations. `index.ts` converts each into a RuleResult.
 *
 * No regex literals. No string-literal arrays > 5.
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  BUILD_TOOL_TOKENS,
  EXPORTS_BLOCK_KEYS,
  MANIFEST_MUTATION_TOKENS,
  PAYLOAD_FILENAME_SUBSTRINGS,
  PUBLISH_LIFECYCLE_HOOKS,
  SYSTEM_COMMAND_BIN_NAMES,
} from "./data/manifest-vocabulary.js";

const PUBLISH_HOOK_SET: ReadonlySet<string> = new Set(Object.keys(PUBLISH_LIFECYCLE_HOOKS));
const MUTATION_SET: ReadonlySet<string> = new Set(Object.keys(MANIFEST_MUTATION_TOKENS));
const BUILD_TOOL_SET: ReadonlySet<string> = new Set(Object.keys(BUILD_TOOL_TOKENS));
const SYSTEM_COMMAND_SET: ReadonlySet<string> = new Set(
  Object.keys(SYSTEM_COMMAND_BIN_NAMES),
);
const PAYLOAD_SUBSTRING_SET: ReadonlySet<string> = new Set(
  Object.keys(PAYLOAD_FILENAME_SUBSTRINGS),
);
const EXPORTS_BLOCK_SET: ReadonlySet<string> = new Set(Object.keys(EXPORTS_BLOCK_KEYS));

const MANIFEST_SUBSTRING = "package.json";

// ─── Public types ──────────────────────────────────────────────────────────

export type L5PrimitiveKind =
  | "prepublish-manifest-mutation"
  | "bin-system-shadow"
  | "bin-hidden-target"
  | "exports-divergence"
  | "exports-package-json-block";

export interface L5Primitive {
  kind: L5PrimitiveKind;
  /** Structured Location for the specific offending node. */
  location: Location;
  /** Textual observation a reviewer sees. */
  observed: string;
  /** Detail string for the confidence-factor rationale. */
  detail: string;
  /**
   * True when this primitive should also emit an L14 companion finding
   * (bin-system-shadow, bin-hidden-target, exports-divergence).
   */
  emitL14Companion: boolean;
}

export interface L5Context {
  /** Location of the manifest object (file root or AST literal). */
  manifestLocation: Location;
  /** Whether the manifest was sourced from an actual package.json file. */
  fromPackageJsonFile: boolean;
  /** Observed `publishConfig.provenance` — present ⇒ mitigation signal. */
  hasProvenanceField: boolean;
  /** All primitives observed under this manifest. */
  primitives: L5Primitive[];
}

export interface L5GatherResult {
  file: string;
  isTestFile: boolean;
  contexts: L5Context[];
}

// ─── Entry point ───────────────────────────────────────────────────────────

const SYNTHETIC_FILE = "<source>";

export function gatherL5(context: AnalysisContext): L5GatherResult {
  const out: L5Context[] = [];
  const file = firstFileName(context.source_files) ?? SYNTHETIC_FILE;
  const isTestFile = isTestFileName(file);

  if (isTestFile) return { file, isTestFile, contexts: [] };

  // Phase 1: package.json files (source_files keys that match).
  if (context.source_files && context.source_files.size > 0) {
    for (const [path, text] of context.source_files) {
      if (!path.endsWith("package.json")) continue;
      if (path.includes("node_modules")) continue;
      const parsed = tryParseJson(text);
      if (parsed === null || typeof parsed !== "object") continue;
      const ctx = analyzeManifestObject(parsed as Record<string, unknown>, {
        kind: "config",
        file: path,
        json_pointer: "/",
      });
      if (ctx.primitives.length > 0) out.push(ctx);
    }
  }

  // Phase 2: object-literals embedded in source code.
  if (context.source_code) {
    const analysisFile = file === SYNTHETIC_FILE ? "<source>" : file;
    const sf = ts.createSourceFile(
      analysisFile,
      context.source_code,
      ts.ScriptTarget.Latest,
      true,
    );
    const visit = (node: ts.Node): void => {
      if (ts.isObjectLiteralExpression(node) && looksLikeManifestLiteral(node)) {
        const manifestObj = literalToObject(node);
        if (manifestObj !== null) {
          const ctx = analyzeManifestObject(manifestObj, locOf(sf, analysisFile, node));
          if (ctx.primitives.length > 0) out.push(ctx);
        }
      }
      ts.forEachChild(node, visit);
    };
    ts.forEachChild(sf, visit);
  }

  return { file, isTestFile, contexts: out };
}

// ─── Manifest analysis ─────────────────────────────────────────────────────

function analyzeManifestObject(
  manifest: Record<string, unknown>,
  manifestLocation: Location,
): L5Context {
  const primitives: L5Primitive[] = [];

  const scripts = manifest.scripts;
  if (isStringRecord(scripts)) {
    for (const hook of Object.keys(scripts)) {
      if (!PUBLISH_HOOK_SET.has(hook)) continue;
      const command = scripts[hook];
      if (typeof command !== "string") continue;
      const mutation = detectManifestMutation(command);
      if (mutation === null) continue;
      primitives.push({
        kind: "prepublish-manifest-mutation",
        location: locWithPointer(manifestLocation, `/scripts/${hook}`),
        observed: `${hook}: ${command.slice(0, 160)}`,
        detail:
          `Publish-lifecycle hook "${hook}" invokes ${mutation.tokens.join(", ")} ` +
          `and references "${MANIFEST_SUBSTRING}"${
            mutation.hasBuildTool ? " alongside a build-tool invocation" : ""
          }. ` +
          `The hook runs on the PUBLISHER's machine between repository commit and ` +
          `tarball creation — any edit to package.json here diverges the ` +
          `installed manifest from the committed one.`,
        emitL14Companion: false,
      });
    }
  }

  const bin = manifest.bin;
  if (isStringRecord(bin)) {
    for (const [name, targetPath] of Object.entries(bin)) {
      if (typeof targetPath !== "string") continue;
      if (SYSTEM_COMMAND_SET.has(name.toLowerCase())) {
        primitives.push({
          kind: "bin-system-shadow",
          location: locWithPointer(manifestLocation, `/bin/${name}`),
          observed: `"${name}": "${targetPath}"`,
          detail:
            `bin entry name "${name}" exactly matches a common system command. ` +
            `Global installation of this package symlinks node_modules/.bin/${name} ` +
            `ahead of /usr/bin/${name} in PATH, silently shadowing the system utility.`,
          emitL14Companion: true,
        });
      }
      const filename = pathBasename(targetPath);
      if (filename.startsWith(".") || filename.startsWith("__")) {
        primitives.push({
          kind: "bin-hidden-target",
          location: locWithPointer(manifestLocation, `/bin/${name}`),
          observed: `"${name}": "${targetPath}"`,
          detail:
            `bin target filename starts with "." or "__" — normal directory ` +
            `listings and tarball extractions hide the file by default, so a ` +
            `reviewer examining the installed package would miss the actual ` +
            `code path that gets executed when "${name}" is invoked.`,
          emitL14Companion: true,
        });
      }
    }
  } else if (typeof bin === "string") {
    const filename = pathBasename(bin);
    if (filename.startsWith(".") || filename.startsWith("__")) {
      primitives.push({
        kind: "bin-hidden-target",
        location: locWithPointer(manifestLocation, "/bin"),
        observed: `"bin": "${bin}"`,
        detail: `bin target filename starts with "." or "__" — concealed entry point.`,
        emitL14Companion: true,
      });
    }
  }

  const exportsField = manifest.exports;
  if (exportsField !== null && typeof exportsField === "object" && !Array.isArray(exportsField)) {
    const exportsObj = exportsField as Record<string, unknown>;
    // exports-divergence (exports["."] { import, require } with payload substring)
    const dot = exportsObj["."];
    if (dot !== undefined && typeof dot === "object" && dot !== null && !Array.isArray(dot)) {
      const dotObj = dot as Record<string, unknown>;
      const importPath = typeof dotObj.import === "string" ? dotObj.import : null;
      const requirePath = typeof dotObj.require === "string" ? dotObj.require : null;
      if (importPath !== null && requirePath !== null && importPath !== requirePath) {
        const suspicious = [importPath, requirePath].find((p) =>
          containsPayloadSubstring(p),
        );
        if (suspicious !== undefined) {
          primitives.push({
            kind: "exports-divergence",
            location: locWithPointer(manifestLocation, "/exports/."),
            observed: `import: "${importPath}", require: "${requirePath}"`,
            detail:
              `Conditional exports serve different files for ESM ("${importPath}") ` +
              `and CJS ("${requirePath}") consumers AND the divergent path ` +
              `contains a payload-shaped filename substring. This is the dual-format ` +
              `payload-delivery primitive documented in the Socket.dev 2025 exports-map ` +
              `abuse research.`,
            emitL14Companion: true,
          });
        }
      }
    }
    // exports["./package.json"] = null/false (audit-blocking)
    for (const blockKey of EXPORTS_BLOCK_SET) {
      if (blockKey in exportsObj) {
        const val = exportsObj[blockKey];
        if (val === null || val === false) {
          primitives.push({
            kind: "exports-package-json-block",
            location: locWithPointer(manifestLocation, `/exports${blockKey}`),
            observed: `"${blockKey}": ${val === null ? "null" : "false"}`,
            detail:
              `exports["${blockKey}"] is set to ${val === null ? "null" : "false"}, ` +
              `blocking audit tools (npm outdated, dependency-cruiser, socket-cli) ` +
              `from reading the installed package.json at runtime. This is a strong ` +
              `amplifier of any other manifest-confusion primitive in this manifest.`,
            emitL14Companion: false,
          });
        }
      }
    }
  }

  const publishConfig = manifest.publishConfig;
  let hasProvenanceField = false;
  if (publishConfig !== null && typeof publishConfig === "object") {
    const pc = publishConfig as Record<string, unknown>;
    if (pc.provenance === true) hasProvenanceField = true;
  }

  return {
    manifestLocation,
    fromPackageJsonFile: manifestLocation.kind === "config",
    hasProvenanceField,
    primitives,
  };
}

// ─── Helpers ───────────────────────────────────────────────────────────────

function detectManifestMutation(command: string): { tokens: string[]; hasBuildTool: boolean } | null {
  // Only fire if the command references package.json AND contains a mutation token.
  if (!command.includes(MANIFEST_SUBSTRING)) return null;
  const tokens: string[] = [];
  let hasBuildTool = false;
  for (const tok of MUTATION_SET) {
    // word-boundary check: the token must appear followed by whitespace, start, or punctuation.
    if (appearsAsCommandToken(command, tok)) tokens.push(tok);
  }
  if (tokens.length === 0) return null;
  for (const tool of BUILD_TOOL_SET) {
    if (appearsAsCommandToken(command, tool)) {
      hasBuildTool = true;
      break;
    }
  }
  return { tokens, hasBuildTool };
}

function appearsAsCommandToken(command: string, token: string): boolean {
  const idx = command.indexOf(token);
  if (idx === -1) return false;
  // Token must be either at start, preceded by a command separator
  // (whitespace / ; | & () / tab / newline), and similarly followed by
  // a separator or end-of-string — so the token is not part of a larger
  // identifier.
  const before = idx === 0 ? "" : command[idx - 1];
  const after = command[idx + token.length] ?? "";
  const leftOk = idx === 0 || isCommandSeparator(before);
  const rightOk = after === "" || isCommandSeparator(after);
  return leftOk && rightOk;
}

function isCommandSeparator(ch: string): boolean {
  return (
    ch === " " ||
    ch === "\t" ||
    ch === "\n" ||
    ch === "\r" ||
    ch === ";" ||
    ch === "|" ||
    ch === "&" ||
    ch === "(" ||
    ch === ")"
  );
}

function containsPayloadSubstring(path: string): boolean {
  const lower = path.toLowerCase();
  for (const sub of PAYLOAD_SUBSTRING_SET) {
    if (lower.includes(sub)) return true;
  }
  const filename = pathBasename(path);
  if (filename.startsWith(".") || filename.startsWith("__")) return true;
  return false;
}

function pathBasename(p: string): string {
  const i = Math.max(p.lastIndexOf("/"), p.lastIndexOf("\\"));
  return i === -1 ? p : p.slice(i + 1);
}

function isStringRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function tryParseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function locWithPointer(base: Location, pointerSuffix: string): Location {
  if (base.kind === "config") {
    const existing = base.json_pointer === "/" ? "" : base.json_pointer;
    return { kind: "config", file: base.file, json_pointer: `${existing}${pointerSuffix}` };
  }
  // For source-kind locations we keep the line/col from the enclosing literal;
  // the json_pointer is returned via a config-kind Location in a parallel channel
  // by the caller.
  return base;
}

function firstFileName(source_files: AnalysisContext["source_files"]): string | null {
  if (!source_files || source_files.size === 0) return null;
  return Array.from(source_files.keys())[0];
}

function isTestFileName(name: string): boolean {
  const n = name.toLowerCase();
  return (
    n.endsWith(".test.ts") ||
    n.endsWith(".test.js") ||
    n.endsWith(".spec.ts") ||
    n.endsWith(".spec.js") ||
    n.includes("__tests__")
  );
}

// ─── AST helpers ───────────────────────────────────────────────────────────

function locOf(sf: ts.SourceFile, file: string, node: ts.Node): Location {
  const start = node.getStart(sf);
  const { line, character } = sf.getLineAndCharacterOfPosition(start);
  return { kind: "source", file, line: line + 1, col: character + 1 };
}

function looksLikeManifestLiteral(node: ts.ObjectLiteralExpression): boolean {
  // The literal must have a `scripts`, `bin`, or `exports` top-level key.
  let hasScripts = false;
  let hasBin = false;
  let hasExports = false;
  for (const prop of node.properties) {
    if (!ts.isPropertyAssignment(prop)) continue;
    const key = propertyKeyName(prop);
    if (key === "scripts") hasScripts = true;
    if (key === "bin") hasBin = true;
    if (key === "exports") hasExports = true;
  }
  return hasScripts || hasBin || hasExports;
}

function propertyKeyName(prop: ts.PropertyAssignment): string | null {
  if (ts.isIdentifier(prop.name)) return prop.name.text;
  if (ts.isStringLiteral(prop.name)) return prop.name.text;
  return null;
}

/**
 * Best-effort conversion from an AST object-literal to a plain JS object.
 * Only string / boolean / null values and nested object-literals with the
 * same property types are captured — anything else (spread, computed
 * property, function call) is omitted, because static analysis cannot
 * soundly interpret it.
 */
function literalToObject(node: ts.ObjectLiteralExpression): Record<string, unknown> | null {
  const out: Record<string, unknown> = {};
  for (const prop of node.properties) {
    if (!ts.isPropertyAssignment(prop)) continue;
    const key = propertyKeyName(prop);
    if (key === null) continue;
    const value = interpretValue(prop.initializer);
    if (value === undefined) continue;
    out[key] = value;
  }
  return out;
}

function interpretValue(node: ts.Expression): unknown {
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
  if (node.kind === ts.SyntaxKind.TrueKeyword) return true;
  if (node.kind === ts.SyntaxKind.FalseKeyword) return false;
  if (node.kind === ts.SyntaxKind.NullKeyword) return null;
  if (ts.isNumericLiteral(node)) return Number(node.text);
  if (ts.isObjectLiteralExpression(node)) {
    const nested: Record<string, unknown> = {};
    for (const prop of node.properties) {
      if (!ts.isPropertyAssignment(prop)) continue;
      const key = propertyKeyName(prop);
      if (key === null) continue;
      const v = interpretValue(prop.initializer);
      if (v !== undefined) nested[key] = v;
    }
    return nested;
  }
  if (ts.isArrayLiteralExpression(node)) {
    const arr: unknown[] = [];
    for (const el of node.elements) {
      const v = interpretValue(el);
      if (v !== undefined) arr.push(v);
    }
    return arr;
  }
  return undefined;
}
