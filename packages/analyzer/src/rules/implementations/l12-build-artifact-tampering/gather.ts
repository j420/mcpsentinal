/**
 * L12 — Build Artifact Tampering: fact gatherer.
 *
 * Two sources are scanned:
 *
 *   1. package.json — the scripts object is inspected for
 *      post-test lifecycle hooks (postbuild, prepublishOnly,
 *      prepack, postpack) whose command references a tamper verb
 *      (sed / awk / perl / patch / cat >> / echo >> / tee) AND a
 *      build-output directory (dist/ / build/ / out/ / lib/).
 *
 *   2. CI workflow YAML (.github/workflows/*.yml) — each run: line
 *      is checked for the same tamper verb + build-dir combination,
 *      optionally amplified by the download-artifact / upload-
 *      artifact markers that indicate an inter-job tamper.
 *
 * The rule output structure is L12Fact[]; index.ts builds the chain.
 *
 * Zero regex literals. Zero string-literal arrays > 5.
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  BUILD_OUTPUT_DIRS,
  BUILD_TOOL_TOKENS,
  CI_WORKFLOW_TAMPER_MARKERS,
  POST_TEST_LIFECYCLE_HOOKS,
  TAMPER_VERB_TOKENS,
} from "./data/tamper-vocabulary.js";

const POST_TEST_HOOK_SET: ReadonlySet<string> = new Set(Object.keys(POST_TEST_LIFECYCLE_HOOKS));
const TAMPER_VERB_SET: ReadonlySet<string> = new Set(Object.keys(TAMPER_VERB_TOKENS));
const BUILD_DIR_SET: ReadonlySet<string> = new Set(Object.keys(BUILD_OUTPUT_DIRS));
const BUILD_TOOL_SET: ReadonlySet<string> = new Set(Object.keys(BUILD_TOOL_TOKENS));
const CI_MARKER_SET: ReadonlySet<string> = new Set(Object.keys(CI_WORKFLOW_TAMPER_MARKERS));

// ─── Public types ──────────────────────────────────────────────────────────

export type L12FactKind =
  | "manifest-lifecycle-tamper"
  | "ci-workflow-tamper";

export interface L12Fact {
  kind: L12FactKind;
  /** Structured Location of the offending line/script. */
  location: Location;
  /** Verbatim observation (trimmed to 200 chars). */
  observed: string;
  /** Which post-test hook fired (manifest) or the workflow filename (CI). */
  hookOrWorkflow: string;
  /** Tamper verbs seen in this command. */
  tamperVerbs: string[];
  /** Build-output directories the tamper targets. */
  buildDirs: string[];
  /** Whether a build-tool token also appears in the same chain. */
  buildToolCamouflage: boolean;
  /** Whether download-artifact / upload-artifact markers appear nearby (CI only). */
  artifactFetch: boolean;
  /** Whether publishConfig.provenance: true was observed in manifest. */
  provenancePresent: boolean;
}

export interface L12GatherResult {
  isTestFile: boolean;
  facts: L12Fact[];
}

// ─── Entry point ───────────────────────────────────────────────────────────

export function gatherL12(context: AnalysisContext): L12GatherResult {
  const facts: L12Fact[] = [];
  const provenancePresent = detectProvenance(context);

  // Phase 1: package.json files.
  if (context.source_files && context.source_files.size > 0) {
    for (const [path, text] of context.source_files) {
      if (path.includes("node_modules")) continue;
      if (path.endsWith("package.json")) {
        const parsed = safeParse(text);
        if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) {
          facts.push(...factsFromManifest(parsed as Record<string, unknown>, path, provenancePresent));
        }
      }
      if (path.includes(".github/workflows/") && (path.endsWith(".yml") || path.endsWith(".yaml"))) {
        facts.push(...factsFromWorkflow(text, path, provenancePresent));
      }
    }
  }

  // Phase 2: embedded manifest literals in source code (covers generated configs).
  if (context.source_code && context.source_code.includes("scripts")) {
    const file = firstFileName(context.source_files) ?? "<source>";
    if (isTestFileName(file)) {
      return { isTestFile: true, facts: [] };
    }
    const sf = ts.createSourceFile(file, context.source_code, ts.ScriptTarget.Latest, true);
    const visit = (node: ts.Node): void => {
      if (ts.isObjectLiteralExpression(node)) {
        for (const prop of node.properties) {
          if (!ts.isPropertyAssignment(prop)) continue;
          const key = propertyKeyName(prop);
          if (key !== "scripts") continue;
          if (!ts.isObjectLiteralExpression(prop.initializer)) continue;
          for (const scriptProp of prop.initializer.properties) {
            if (!ts.isPropertyAssignment(scriptProp)) continue;
            const hookName = propertyKeyName(scriptProp);
            if (hookName === null || !POST_TEST_HOOK_SET.has(hookName)) continue;
            const command = literalText(scriptProp.initializer);
            if (command === null) continue;
            const analysis = analyseCommand(command);
            if (analysis === null) continue;
            facts.push({
              kind: "manifest-lifecycle-tamper",
              location: locOf(sf, file, scriptProp),
              observed: command.slice(0, 200),
              hookOrWorkflow: hookName,
              tamperVerbs: analysis.tamperVerbs,
              buildDirs: analysis.buildDirs,
              buildToolCamouflage: analysis.buildToolCamouflage,
              artifactFetch: false,
              provenancePresent,
            });
          }
        }
      }
      ts.forEachChild(node, visit);
    };
    ts.forEachChild(sf, visit);
  }

  return { isTestFile: false, facts };
}

// ─── Manifest scan ─────────────────────────────────────────────────────────

function factsFromManifest(
  manifest: Record<string, unknown>,
  path: string,
  provenancePresent: boolean,
): L12Fact[] {
  const out: L12Fact[] = [];
  const scripts = manifest.scripts;
  if (!scripts || typeof scripts !== "object" || Array.isArray(scripts)) return out;
  const scriptsObj = scripts as Record<string, unknown>;
  for (const [hook, command] of Object.entries(scriptsObj)) {
    if (!POST_TEST_HOOK_SET.has(hook)) continue;
    if (typeof command !== "string") continue;
    const analysis = analyseCommand(command);
    if (analysis === null) continue;
    out.push({
      kind: "manifest-lifecycle-tamper",
      location: { kind: "config", file: path, json_pointer: `/scripts/${hook}` },
      observed: command.slice(0, 200),
      hookOrWorkflow: hook,
      tamperVerbs: analysis.tamperVerbs,
      buildDirs: analysis.buildDirs,
      buildToolCamouflage: analysis.buildToolCamouflage,
      artifactFetch: false,
      provenancePresent,
    });
  }
  return out;
}

// ─── Workflow YAML scan ────────────────────────────────────────────────────

function factsFromWorkflow(
  text: string,
  path: string,
  provenancePresent: boolean,
): L12Fact[] {
  const out: L12Fact[] = [];
  const lines = text.split("\n");
  // Look for any "run:" line whose value references both a tamper verb and
  // a build directory. Amplify with artifact markers anywhere in the file.
  let artifactMentioned = false;
  for (const line of lines) {
    for (const marker of CI_MARKER_SET) {
      if (line.includes(marker)) {
        artifactMentioned = true;
        break;
      }
    }
    if (artifactMentioned) break;
  }
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (!trimmed.startsWith("run:") && !trimmed.startsWith("-") && !trimmed.includes("|")) {
      // Standard shape: run: <command> | on a single line, or a block under run:
      // We still allow lines that begin with a hyphen (inline array item).
    }
    const analysis = analyseCommand(trimmed);
    if (analysis === null) continue;
    out.push({
      kind: "ci-workflow-tamper",
      location: { kind: "source", file: path, line: i + 1, col: 1 },
      observed: trimmed.slice(0, 200),
      hookOrWorkflow: path,
      tamperVerbs: analysis.tamperVerbs,
      buildDirs: analysis.buildDirs,
      buildToolCamouflage: analysis.buildToolCamouflage,
      artifactFetch: artifactMentioned,
      provenancePresent,
    });
  }
  return out;
}

// ─── Command analysis ──────────────────────────────────────────────────────

interface CommandAnalysis {
  tamperVerbs: string[];
  buildDirs: string[];
  buildToolCamouflage: boolean;
}

function analyseCommand(command: string): CommandAnalysis | null {
  const tamperVerbs: string[] = [];
  for (const verb of TAMPER_VERB_SET) {
    if (appearsAsCommandToken(command, verb)) tamperVerbs.push(verb);
  }
  if (tamperVerbs.length === 0) return null;

  const buildDirs: string[] = [];
  for (const dir of BUILD_DIR_SET) {
    // Match the dir name followed by a "/" — e.g. "dist/", "build/".
    const probe = `${dir}/`;
    if (command.includes(probe)) buildDirs.push(dir);
  }
  if (buildDirs.length === 0) return null;

  let buildToolCamouflage = false;
  for (const tool of BUILD_TOOL_SET) {
    if (appearsAsCommandToken(command, tool)) {
      buildToolCamouflage = true;
      break;
    }
  }

  return { tamperVerbs, buildDirs, buildToolCamouflage };
}

function appearsAsCommandToken(command: string, token: string): boolean {
  // Multi-char tokens like "cat >>" contain a space; search directly.
  if (token.includes(" ") || token.includes(">")) return command.includes(token);
  const idx = command.indexOf(token);
  if (idx === -1) return false;
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

// ─── Helpers ───────────────────────────────────────────────────────────────

function detectProvenance(context: AnalysisContext): boolean {
  if (!context.source_files) return false;
  for (const [path, text] of context.source_files) {
    if (!path.endsWith("package.json")) continue;
    const parsed = safeParse(text);
    if (parsed === null || typeof parsed !== "object") continue;
    const pc = (parsed as Record<string, unknown>).publishConfig;
    if (pc !== null && typeof pc === "object" && !Array.isArray(pc)) {
      if ((pc as Record<string, unknown>).provenance === true) return true;
    }
  }
  return false;
}

function safeParse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function locOf(sf: ts.SourceFile, file: string, node: ts.Node): Location {
  const start = node.getStart(sf);
  const { line, character } = sf.getLineAndCharacterOfPosition(start);
  return { kind: "source", file, line: line + 1, col: character + 1 };
}

function propertyKeyName(prop: ts.PropertyAssignment): string | null {
  if (ts.isIdentifier(prop.name)) return prop.name.text;
  if (ts.isStringLiteral(prop.name)) return prop.name.text;
  return null;
}

function literalText(node: ts.Expression): string | null {
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
  return null;
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
