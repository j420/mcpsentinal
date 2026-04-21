/**
 * L13 — Build Credential File Theft: fact gatherer.
 *
 * Two orthogonal signal sources:
 *
 *   1. AST taint via the shared taint-rule-kit — source is a file-read
 *      returning a credential-file path, sink is a network egress
 *      (ssrf / command_execution). When a full chain fires, the
 *      credential bytes provably reach the network.
 *
 *   2. Structural fallback — walk the TypeScript AST of every source
 *      file; any `fs.readFile*` / `open*` / `createReadStream` call
 *      whose argument text contains a credential-file substring is
 *      recorded as a "file-read" fact (no taint to network required).
 *      Also walk Dockerfile-shaped files for `COPY <src> <dst>` lines
 *      whose source path contains a credential-file substring.
 *
 * Zero regex literals outside `data/`.
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  gatherTaintFacts,
  type TaintFact,
} from "../_shared/taint-rule-kit/index.js";
import {
  CREDENTIAL_FILE_SUBSTRINGS,
  L13_AST_NETWORK_SINK_CATEGORIES,
  L13_LIGHTWEIGHT_NETWORK_SINK_CATEGORIES,
  L13_CHARTER_SANITISERS,
  DOCKERFILE_COPY_TOKENS,
} from "./data/config.js";

// ─── Fact types ────────────────────────────────────────────────────────────

export type L13FactKind =
  | "taint-cred-to-network" // full source→sink taint chain
  | "cred-file-read-direct" // fs.readFile(".npmrc") — no network sink observed
  | "dockerfile-copy-cred"; // COPY .npmrc /image/path

export interface L13Fact {
  kind: L13FactKind;
  /** source-kind for code facts; config-kind for Dockerfile facts. */
  location: Location;
  /** Dangerous fragment (call text or Dockerfile line). */
  observed: string;
  /** The credential-file substring that matched. */
  credFile: string;
  /** Populated when kind === "taint-cred-to-network". */
  taintFact: TaintFact | null;
}

export interface L13GatherResult {
  mode: "absent" | "test-file" | "facts";
  facts: L13Fact[];
}

export function gatherL13(context: AnalysisContext): L13GatherResult {
  const source = context.source_code;
  if (!source || source.length === 0) {
    return { mode: "absent", facts: [] };
  }

  const facts: L13Fact[] = [];

  // Phase 1: taint chain from file read to network sink.
  const taintResult = gatherTaintFacts(context, {
    ruleId: "L13",
    astSinkCategories: L13_AST_NETWORK_SINK_CATEGORIES,
    lightweightSinkCategories: L13_LIGHTWEIGHT_NETWORK_SINK_CATEGORIES,
    charterSanitisers: L13_CHARTER_SANITISERS,
  });
  if (taintResult.mode === "test-file") {
    return { mode: "test-file", facts: [] };
  }
  if (taintResult.mode === "facts") {
    for (const tf of taintResult.facts) {
      const credMatch = findCredSubstring(tf.sourceExpression) ??
        findCredSubstring(tf.path.map((p) => p.expression).join(" ")) ??
        findCredSubstring(tf.sinkExpression);
      if (!credMatch) continue;
      facts.push({
        kind: "taint-cred-to-network",
        location: tf.sourceLocation,
        observed:
          `${tf.sourceExpression.slice(0, 60)} → ${tf.sinkExpression.slice(0, 60)}`,
        credFile: credMatch,
        taintFact: tf,
      });
    }
  }

  // Phase 2: structural file-read scan — picks up cases where the bytes
  // never reach a network sink we recognise.
  facts.push(...scanFiles(context));

  return { mode: facts.length > 0 ? "facts" : "absent", facts };
}

function scanFiles(context: AnalysisContext): L13Fact[] {
  const out: L13Fact[] = [];
  const files = collectFiles(context);

  for (const [file, text] of files) {
    if (isTestFileShape(file, text)) continue;
    if (isDockerfile(file, text)) {
      out.push(...scanDockerfile(file, text));
    } else {
      out.push(...scanTypeScriptSource(file, text));
    }
  }
  return out;
}

function collectFiles(context: AnalysisContext): Map<string, string> {
  const out = new Map<string, string>();
  if (context.source_files && context.source_files.size > 0) {
    for (const [k, v] of context.source_files) out.set(k, v);
    return out;
  }
  if (context.source_code) {
    out.set("<concatenated-source>", context.source_code);
  }
  return out;
}

function isTestFileShape(file: string, text: string): boolean {
  if (file.endsWith(".test.ts") || file.endsWith(".spec.ts")) return true;
  if (file.endsWith(".test.js") || file.endsWith(".spec.js")) return true;
  if (file.includes("__tests__/") || file.includes("__fixtures__/")) return true;
  const hasRunner =
    text.includes('from "vitest"') ||
    text.includes('from "jest"') ||
    text.includes('from "mocha"');
  const hasSuite = text.includes("describe(");
  return hasRunner && hasSuite;
}

function isDockerfile(file: string, text: string): boolean {
  if (file.endsWith("Dockerfile")) return true;
  if (file.includes("Dockerfile")) return true;
  // Structural signal — file starts with FROM or contains RUN / COPY / WORKDIR.
  const trimmed = text.trimStart();
  if (trimmed.startsWith("FROM ") || trimmed.startsWith("FROM\t")) return true;
  return false;
}

function scanDockerfile(file: string, text: string): L13Fact[] {
  const out: L13Fact[] = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    let matchedInstruction: string | null = null;
    for (const tok of DOCKERFILE_COPY_TOKENS) {
      if (line.startsWith(tok)) {
        matchedInstruction = tok.trim();
        break;
      }
    }
    if (!matchedInstruction) continue;
    const cred = findCredSubstring(line);
    if (!cred) continue;
    out.push({
      kind: "dockerfile-copy-cred",
      location: {
        kind: "config",
        file,
        json_pointer: `/instructions/${i}`,
      },
      observed: line.trim().slice(0, 240),
      credFile: cred,
      taintFact: null,
    });
  }
  return out;
}

function scanTypeScriptSource(file: string, text: string): L13Fact[] {
  let sf: ts.SourceFile;
  try {
    sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
  } catch {
    return [];
  }

  const out: L13Fact[] = [];

  ts.forEachChild(sf, function visit(node) {
    if (ts.isCallExpression(node)) {
      const fact = detectCredFileRead(node, sf, file);
      if (fact) out.push(fact);
    }
    ts.forEachChild(node, visit);
  });

  return out;
}

function detectCredFileRead(
  call: ts.CallExpression,
  sf: ts.SourceFile,
  file: string,
): L13Fact | null {
  const callee = resolveCalleeName(call);
  if (!callee) return null;
  if (
    callee !== "readFile" &&
    callee !== "readFileSync" &&
    callee !== "open" &&
    callee !== "openSync" &&
    callee !== "createReadStream" &&
    callee !== "readlink" &&
    callee !== "readlinkSync"
  ) {
    return null;
  }
  // Inspect the first argument text and any string literal / template it contains.
  const firstArg = call.arguments[0];
  if (!firstArg) return null;
  const argText = firstArg.getText(sf);
  const cred = findCredSubstring(argText);
  if (!cred) return null;

  const { line, col } = toLineCol(sf, call.getStart(sf));
  return {
    kind: "cred-file-read-direct",
    location: { kind: "source", file, line, col },
    observed: call.getText(sf).slice(0, 240),
    credFile: cred,
    taintFact: null,
  };
}

function resolveCalleeName(call: ts.CallExpression): string | null {
  const expr = call.expression;
  if (ts.isIdentifier(expr)) return expr.text;
  if (ts.isPropertyAccessExpression(expr) && ts.isIdentifier(expr.name)) {
    return expr.name.text;
  }
  return null;
}

function findCredSubstring(text: string): string | null {
  for (const tok of CREDENTIAL_FILE_SUBSTRINGS) {
    if (text.includes(tok)) return tok;
  }
  return null;
}

function toLineCol(sf: ts.SourceFile, pos: number): { line: number; col: number } {
  const { line, character } = sf.getLineAndCharacterOfPosition(pos);
  return { line: line + 1, col: character + 1 };
}
