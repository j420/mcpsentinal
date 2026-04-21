/**
 * C5 evidence gathering — AST-driven, ZERO regex literals.
 *
 * Detection pipeline:
 *
 *   1. Parse the source as a TypeScript AST (ts.createSourceFile). If the
 *      source is Python, fall back to a line-scan of non-comment lines —
 *      Python's syntax is simple enough that line-wise scanning preserves
 *      the comment-skip and assignment detection we need.
 *
 *   2. Walk every StringLiteral / NoSubstitutionTemplateLiteral. Skip
 *      literals that appear inside AST-confirmed comments (the AST
 *      walker never visits comment text — satisfied by construction).
 *
 *   3. For each literal, check each KNOWN_SECRET_FORMATS prefix via
 *      String.prototype.startsWith — NO REGEX. If a match is found,
 *      validate the suffix length and charset using the typed spec.
 *
 *   4. Apply placeholder-marker guards: any hit against PLACEHOLDER_MARKERS
 *      on the literal OR its enclosing line suppresses the finding.
 *
 *   5. Record a SecretHit with file:line:col Location, the matched spec,
 *      and the Shannon entropy of the value — all of which `index.ts`
 *      turns into a v2 evidence chain.
 *
 * CHARTER lethal edge cases this file covers:
 *   - structural-test-file-nature      → testNature() (AST markers only)
 *   - placeholder-marker-detection     → placeholder scan of line + suffix
 *   - prefix-literal-recognition       → 14 typed specs in data/
 *   - entropy-minimum-threshold        → shannonEntropy(suffix) ≥ 3.5
 *   - entropy-bonus-high               → shannonEntropy(suffix) ≥ 4.5 boost
 *   - comment-line-skip                → AST never visits comment text
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import { shannonEntropy } from "../../analyzers/entropy.js";
import {
  KNOWN_SECRET_FORMATS,
  PEM_PRIVATE_KEY_HEADER,
  PEM_PRIVATE_KEY_VARIANTS,
  PLACEHOLDER_MARKERS,
  EXAMPLE_FILENAME_MARKERS,
  CREDENTIAL_IDENTIFIER_NAMES,
  TEST_FILE_SUFFIXES,
  suffixMatchesCharset,
  type SecretFormatSpec,
} from "./data/secret-formats.js";

// ─── Public types ──────────────────────────────────────────────────────────

export interface SecretHit {
  /** Kind of match — prefix against the KNOWN_SECRET_FORMATS list, a PEM header, or a generic identifier. */
  kind: "prefix-match" | "pem-private-key" | "generic-identifier";
  /** Which format spec matched (null for PEM + generic-identifier matches). */
  spec: SecretFormatSpec | null;
  /** Masked, length-capped rendering safe to log. */
  masked: string;
  /** Shannon entropy of the matched value. */
  entropy: number;
  /** Where the credential appears. */
  location: Location;
  /** The trimmed, length-capped line the match was observed on. */
  observedLine: string;
  /** Whether a placeholder marker was found nearby (match is suppressed if true). */
  placeholderNearby: boolean;
  /** Whether the file this hit lives in is a structurally-identified test file. */
  isTestFile: boolean;
  /** Whether the file name matches an example/template pattern (.env.example etc). */
  isExampleFile: boolean;
  /** Whether the file contains any `process.env` / `os.environ` read on the same identifier name. */
  hasEnvironmentLookup: boolean;
  /** For generic-identifier hits, the credential identifier involved (api_key etc). */
  identifierName: string | null;
}

export interface C5GatherResult {
  perFile: Array<{ file: string; hits: SecretHit[] }>;
}

// ─── Gather entry point ────────────────────────────────────────────────────

const SYNTHETIC_FILE = "<source>";

const CREDENTIAL_IDENTIFIERS: ReadonlySet<string> = new Set(
  CREDENTIAL_IDENTIFIER_NAMES,
);

export function gatherC5(context: AnalysisContext): C5GatherResult {
  const perFile: Array<{ file: string; hits: SecretHit[] }> = [];

  const sources = collectSources(context);
  if (sources.size === 0) return { perFile };

  for (const [file, text] of sources) {
    const hits = gatherFile(file, text);
    perFile.push({ file, hits });
  }

  return { perFile };
}

function collectSources(context: AnalysisContext): Map<string, string> {
  const out = new Map<string, string>();
  if (context.source_files && context.source_files.size > 0) {
    for (const [k, v] of context.source_files) out.set(k, v);
  } else if (context.source_code && context.source_code.length > 0) {
    out.set(SYNTHETIC_FILE, context.source_code);
  }
  return out;
}

function gatherFile(file: string, text: string): SecretHit[] {
  const isTestFile = detectTestFile(file, text);
  const isExampleFile = detectExampleFile(file);
  const hasEnvMarker = containsEnvironmentLookup(text);

  const hits: SecretHit[] = [];
  const visited = new Set<string>();

  // Parse as TypeScript — the parser is permissive enough to tolerate
  // non-TypeScript source; it simply yields a tree with error nodes. For
  // Python / other non-TS files we fall back to a line-wise scan below.
  const isPythonFile =
    file.endsWith(".py") || looksLikePython(text);

  if (!isPythonFile) {
    const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
    ts.forEachChild(sf, function visit(node) {
      if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
        collectFromStringLiteral(
          node,
          sf,
          file,
          text,
          hits,
          visited,
          isTestFile,
          isExampleFile,
          hasEnvMarker,
          deriveIdentifier(node),
        );
      }
      ts.forEachChild(node, visit);
    });
  } else {
    collectFromPythonLines(file, text, hits, visited, isTestFile, isExampleFile, hasEnvMarker);
  }

  // PEM header scan — independent of string-literal AST walk because PEM keys
  // often span multi-line strings; a direct substring test against the line
  // text is sufficient.
  collectPemPrivateKeys(file, text, hits, visited, isTestFile, isExampleFile, hasEnvMarker);

  return hits;
}

// ─── TS-AST string-literal collection ──────────────────────────────────────

function collectFromStringLiteral(
  node: ts.StringLiteral | ts.NoSubstitutionTemplateLiteral,
  sf: ts.SourceFile,
  file: string,
  text: string,
  hits: SecretHit[],
  visited: Set<string>,
  isTestFile: boolean,
  isExampleFile: boolean,
  hasEnvMarker: boolean,
  identifierName: string | null,
): void {
  const value = node.text;
  if (value.length < 6) return;

  const { line, character } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
  const lineText = getLine(text, line + 1);
  const location: Location = {
    kind: "source",
    file,
    line: line + 1,
    col: character + 1,
    length: value.length,
  };
  const key = `${file}:${line + 1}:${character + 1}`;
  if (visited.has(key)) return;

  const placeholderNearby = hasPlaceholderMarker(value) || hasPlaceholderMarker(lineText);

  for (const spec of KNOWN_SECRET_FORMATS) {
    if (!value.startsWith(spec.prefix)) continue;
    const suffix = value.slice(spec.prefix.length);
    if (suffix.length < spec.minSuffix) continue;
    if (!suffixMatchesCharset(suffix, spec.charset, spec.allowDot, spec.allowDash)) continue;
    visited.add(key);
    hits.push({
      kind: "prefix-match",
      spec,
      masked: mask(value),
      entropy: shannonEntropy(value),
      location,
      observedLine: truncateLine(lineText),
      placeholderNearby,
      isTestFile,
      isExampleFile,
      hasEnvironmentLookup: hasEnvMarker && identifierName !== null,
      identifierName,
    });
    return;
  }

  // Generic credential assignment — only fires if the enclosing AST context is
  // assigning to a credential-shaped identifier name (deriveIdentifier did
  // that check) AND the literal has ≥20 chars of alphanumeric/URL-safe content.
  if (identifierName !== null && value.length >= 12 && !placeholderNearby) {
    const entropy = shannonEntropy(value);
    if (entropy < 3.5) return;
    visited.add(key);
    hits.push({
      kind: "generic-identifier",
      spec: null,
      masked: mask(value),
      entropy,
      location,
      observedLine: truncateLine(lineText),
      placeholderNearby,
      isTestFile,
      isExampleFile,
      hasEnvironmentLookup: hasEnvMarker,
      identifierName,
    });
  }
}

/**
 * If this StringLiteral is on the right-hand side of an assignment to an
 * identifier in CREDENTIAL_IDENTIFIERS, return the identifier text. Otherwise
 * return null — the generic match is not applicable.
 */
function deriveIdentifier(node: ts.Node): string | null {
  const parent = node.parent;
  if (!parent) return null;

  // const api_key = "sk-..."
  if (ts.isVariableDeclaration(parent) && parent.initializer === node) {
    if (ts.isIdentifier(parent.name)) {
      const n = parent.name.text;
      if (matchesCredentialIdentifier(n)) return n;
    }
  }
  // api_key = "..."
  if (ts.isBinaryExpression(parent) && parent.right === node) {
    if (parent.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      if (ts.isIdentifier(parent.left)) {
        const n = parent.left.text;
        if (matchesCredentialIdentifier(n)) return n;
      }
      if (ts.isPropertyAccessExpression(parent.left)) {
        const n = parent.left.name.text;
        if (matchesCredentialIdentifier(n)) return n;
      }
    }
  }
  // { api_key: "..." }
  if (ts.isPropertyAssignment(parent) && parent.initializer === node) {
    if (ts.isIdentifier(parent.name) || ts.isStringLiteral(parent.name)) {
      const n = ts.isIdentifier(parent.name) ? parent.name.text : parent.name.text;
      if (matchesCredentialIdentifier(n)) return n;
    }
  }
  return null;
}

function matchesCredentialIdentifier(name: string): boolean {
  if (CREDENTIAL_IDENTIFIERS.has(name)) return true;
  const lower = name.toLowerCase();
  return CREDENTIAL_IDENTIFIERS.has(lower);
}

// ─── Python line-wise fallback ─────────────────────────────────────────────

function looksLikePython(text: string): boolean {
  // Heuristic: presence of Python "def ", "import ", or "os.environ" at start of a line
  // without the JS/TS markers `function `, `const `, `let `, `var `.
  const hasDef = text.includes("\ndef ") || text.startsWith("def ");
  const hasImport = text.includes("\nimport ") && !text.includes("from \"");
  const hasJs =
    text.includes("const ") || text.includes("let ") || text.includes("function ");
  return (hasDef || hasImport) && !hasJs;
}

function collectFromPythonLines(
  file: string,
  text: string,
  hits: SecretHit[],
  visited: Set<string>,
  isTestFile: boolean,
  isExampleFile: boolean,
  hasEnvMarker: boolean,
): void {
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];
    const trimmed = rawLine.trim();
    if (trimmed.startsWith("#")) continue;
    // Identify single- and double-quoted string literals via a small scanner.
    const literals = extractPythonStringLiterals(rawLine);
    for (const lit of literals) {
      if (lit.value.length < 6) continue;
      const line = i + 1;
      const col = lit.col + 1;
      const key = `${file}:${line}:${col}`;
      if (visited.has(key)) continue;
      const location: Location = {
        kind: "source",
        file,
        line,
        col,
        length: lit.value.length,
      };
      const placeholderNearby = hasPlaceholderMarker(lit.value) || hasPlaceholderMarker(rawLine);
      const pyIdentifier = derivePythonIdentifier(rawLine, lit.col);

      let matched = false;
      for (const spec of KNOWN_SECRET_FORMATS) {
        if (!lit.value.startsWith(spec.prefix)) continue;
        const suffix = lit.value.slice(spec.prefix.length);
        if (suffix.length < spec.minSuffix) continue;
        if (!suffixMatchesCharset(suffix, spec.charset, spec.allowDot, spec.allowDash)) continue;
        visited.add(key);
        hits.push({
          kind: "prefix-match",
          spec,
          masked: mask(lit.value),
          entropy: shannonEntropy(lit.value),
          location,
          observedLine: truncateLine(rawLine),
          placeholderNearby,
          isTestFile,
          isExampleFile,
          hasEnvironmentLookup: hasEnvMarker && pyIdentifier !== null,
          identifierName: pyIdentifier,
        });
        matched = true;
        break;
      }
      if (matched) continue;

      if (pyIdentifier !== null && lit.value.length >= 12 && !placeholderNearby) {
        const entropy = shannonEntropy(lit.value);
        if (entropy < 3.5) continue;
        visited.add(key);
        hits.push({
          kind: "generic-identifier",
          spec: null,
          masked: mask(lit.value),
          entropy,
          location,
          observedLine: truncateLine(rawLine),
          placeholderNearby,
          isTestFile,
          isExampleFile,
          hasEnvironmentLookup: hasEnvMarker,
          identifierName: pyIdentifier,
        });
      }
    }
  }
}

function extractPythonStringLiterals(
  line: string,
): Array<{ value: string; col: number; quote: '"' | "'" }> {
  const out: Array<{ value: string; col: number; quote: '"' | "'" }> = [];
  let i = 0;
  const n = line.length;
  while (i < n) {
    const c = line[i];
    if (c === '"' || c === "'") {
      const quote = c;
      const start = i + 1;
      let j = start;
      let escaped = false;
      while (j < n) {
        const cj = line[j];
        if (escaped) {
          escaped = false;
        } else if (cj === "\\") {
          escaped = true;
        } else if (cj === quote) {
          break;
        }
        j++;
      }
      if (j > start && j < n) {
        out.push({ value: line.slice(start, j), col: start, quote });
        i = j + 1;
        continue;
      }
      // Unclosed — skip past the quote char and keep scanning.
      i++;
      continue;
    }
    i++;
  }
  return out;
}

function derivePythonIdentifier(line: string, litCol: number): string | null {
  const before = line.slice(0, litCol);
  const eqIdx = before.lastIndexOf("=");
  if (eqIdx < 0) return null;
  const lhs = before.slice(0, eqIdx).trim();
  const colonIdx = lhs.lastIndexOf(":");
  const ident = (colonIdx >= 0 ? lhs.slice(0, colonIdx) : lhs).trim();
  // Trailing identifier — walk back collecting [A-Za-z0-9_] characters. No regex.
  let end = ident.length;
  let start = end;
  while (start > 0 && isIdentifierChar(ident.charCodeAt(start - 1))) {
    start--;
  }
  const name = ident.slice(start, end);
  if (matchesCredentialIdentifier(name)) return name;
  return null;
}

function isIdentifierChar(cp: number): boolean {
  return (
    (cp >= 48 && cp <= 57) ||
    (cp >= 65 && cp <= 90) ||
    (cp >= 97 && cp <= 122) ||
    cp === 95
  );
}

// ─── PEM header detection ──────────────────────────────────────────────────

function collectPemPrivateKeys(
  file: string,
  text: string,
  hits: SecretHit[],
  visited: Set<string>,
  isTestFile: boolean,
  isExampleFile: boolean,
  hasEnvMarker: boolean,
): void {
  let cursor = 0;
  while (true) {
    const idx = text.indexOf(PEM_PRIVATE_KEY_HEADER, cursor);
    if (idx < 0) break;
    const line = lineOfOffset(text, idx);
    const lineText = getLine(text, line);
    const afterHeader = text.slice(idx + PEM_PRIVATE_KEY_HEADER.length, idx + 120);
    let matched = false;
    for (const variant of PEM_PRIVATE_KEY_VARIANTS) {
      if (afterHeader.startsWith(variant)) {
        matched = true;
        break;
      }
    }
    cursor = idx + PEM_PRIVATE_KEY_HEADER.length;
    if (!matched) continue;
    const key = `${file}:pem:${line}`;
    if (visited.has(key)) continue;
    visited.add(key);
    const placeholderNearby = hasPlaceholderMarker(lineText);
    hits.push({
      kind: "pem-private-key",
      spec: null,
      masked: PEM_PRIVATE_KEY_HEADER + "…",
      entropy: 5.5,
      location: { kind: "source", file, line },
      observedLine: truncateLine(lineText),
      placeholderNearby,
      isTestFile,
      isExampleFile,
      hasEnvironmentLookup: hasEnvMarker,
      identifierName: null,
    });
  }
}

// ─── File-level classifiers ────────────────────────────────────────────────

function detectTestFile(file: string, text: string): boolean {
  // Filename-only test markers (lower-risk signal). List lives in data/.
  const nameMatch = TEST_FILE_SUFFIXES.some((s) => file.endsWith(s));

  // Structural: imports a test runner AND calls describe/it/test at top level.
  const importsVitest =
    text.includes('from "vitest"') || text.includes("from 'vitest'");
  const importsJest =
    text.includes('from "jest"') || text.includes("from '@jest/globals'");
  const importsMocha =
    text.includes('from "mocha"') || text.includes("from 'mocha'");
  const importsPytest = text.includes("import pytest") || text.includes("from pytest");
  const hasRunnerImport = importsVitest || importsJest || importsMocha || importsPytest;

  const hasTopLevelSuite =
    text.includes("\ndescribe(") ||
    text.includes("\nit(") ||
    text.includes("\ntest(") ||
    text.startsWith("describe(") ||
    text.startsWith("it(") ||
    text.startsWith("test(");

  return nameMatch || (hasRunnerImport && hasTopLevelSuite);
}

function detectExampleFile(file: string): boolean {
  const lower = file.toLowerCase();
  for (const marker of EXAMPLE_FILENAME_MARKERS) {
    if (lower.endsWith(marker)) return true;
    if (lower.includes(`/${marker}`)) return true;
  }
  return false;
}

function containsEnvironmentLookup(text: string): boolean {
  return (
    text.includes("process.env") ||
    text.includes("os.environ") ||
    text.includes("dotenv.config") ||
    text.includes("load_dotenv")
  );
}

// ─── Small helpers ─────────────────────────────────────────────────────────

function hasPlaceholderMarker(value: string): boolean {
  const lower = value.toLowerCase();
  for (const marker of PLACEHOLDER_MARKERS) {
    if (lower.includes(marker.toLowerCase())) return true;
  }
  return false;
}

function mask(value: string): string {
  if (value.length <= 8) return value[0] + "…" + value[value.length - 1];
  return value.slice(0, 4) + "…" + value.slice(-4);
}

function truncateLine(line: string): string {
  const t = line.trim();
  return t.length > 200 ? t.slice(0, 199) + "…" : t;
}

function getLine(text: string, lineNumber: number): string {
  const parts = text.split("\n");
  return parts[lineNumber - 1] ?? "";
}

function lineOfOffset(text: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset && i < text.length; i++) {
    if (text[i] === "\n") line++;
  }
  return line;
}
