/**
 * P8 evidence gathering — AST-based (TypeScript compiler API).
 *
 * Three detection tracks:
 *   1. ECB mode strings — any StringLiteral whose value contains a cipher
 *      family token AND the token "ecb" (case-insensitive).
 *   2. Static IV — VariableDeclaration whose name tokenises to include
 *      iv / nonce / salt and whose initializer is a literal constant or
 *      a Buffer.alloc(N) / new Uint8Array(N) without a subsequent
 *      randomFill call.
 *   3. Math.random() in crypto context — CallExpression whose callee
 *      text is "Math.random" and whose enclosing function body contains
 *      crypto-context tokens (key / secret / iv / hmac / sign / kdf).
 *
 * No regex literals. No long string arrays. Test-file detection is
 * structural (vitest/jest + describe) — charter lethal edge case #4.
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  IV_IDENTIFIER_TOKENS,
  CIPHER_FAMILY_TOKENS,
  CRYPTO_CONTEXT_TOKENS,
  CSPRNG_FINGERPRINTS,
  type P8VariantId,
} from "./data/crypto-vocabulary.js";

// ─── Public types ──────────────────────────────────────────────────────────

export interface P8Fact {
  variant: P8VariantId;
  file: string;
  line: number;
  col: number;
  /** Verbatim snippet trimmed / length-capped. */
  observed: string;
  /** Short description emitted in chain rationale. */
  description: string;
  /** Structured source Location. */
  location: Location;
  /** CSPRNG fingerprint presence in the SAME file. */
  csprngAvailableNearby: boolean;
}

export interface P8GatherResult {
  facts: P8Fact[];
  scannedFiles: string[];
}

// ─── Entry point ───────────────────────────────────────────────────────────

export function gatherP8(context: AnalysisContext): P8GatherResult {
  const facts: P8Fact[] = [];
  const scannedFiles: string[] = [];

  const files = collectCandidateFiles(context);
  for (const [file, text] of files) {
    scannedFiles.push(file);
    const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
    if (isStructuralTestFile(sf)) continue;

    const csprngAvailable = fileContainsCSPRNG(text);
    collectFromAst(sf, file, text, csprngAvailable, facts);
  }

  return { facts, scannedFiles };
}

// ─── Candidate-file discovery ──────────────────────────────────────────────

function collectCandidateFiles(context: AnalysisContext): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  if (context.source_files && context.source_files.size > 0) {
    for (const [path, text] of context.source_files) {
      if (isCandidateSource(path)) out.push([path, text]);
    }
    if (out.length > 0) return out;
  }
  if (context.source_code) {
    out.push(["<concatenated-source>", context.source_code]);
  }
  return out;
}

function isCandidateSource(path: string): boolean {
  const lower = path.toLowerCase();
  return (
    lower.endsWith(".ts") ||
    lower.endsWith(".tsx") ||
    lower.endsWith(".js") ||
    lower.endsWith(".jsx") ||
    lower.endsWith(".mts") ||
    lower.endsWith(".cts") ||
    lower.endsWith(".mjs") ||
    lower.endsWith(".cjs")
  );
}

// ─── AST visitor ───────────────────────────────────────────────────────────

function collectFromAst(
  sf: ts.SourceFile,
  file: string,
  text: string,
  csprngAvailable: boolean,
  facts: P8Fact[],
): void {
  // Resolve simple const bindings: `const mode = "aes-128-ecb"`.
  const constBindings = collectConstBindings(sf);

  const visit = (node: ts.Node): void => {
    // Track 1 — ECB mode via StringLiteral.
    if (ts.isStringLiteral(node)) {
      const val = node.text;
      if (detectsEcbMode(val)) {
        const pos = sf.getLineAndCharacterOfPosition(node.getStart(sf));
        facts.push(makeFact("ecb_mode", `ECB mode cipher: "${val}"`, file, pos, text, csprngAvailable));
      }
    }

    // Track 1a — ECB mode via variable reference (charter lethal edge case #1).
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      ts.isIdentifier(node.expression.expression) &&
      node.expression.expression.text.toLowerCase() === "crypto" &&
      (node.expression.name.text.startsWith("createCipher") ||
        node.expression.name.text.startsWith("createDecipher"))
    ) {
      const firstArg = node.arguments[0];
      if (firstArg && ts.isIdentifier(firstArg)) {
        const bound = constBindings.get(firstArg.text);
        if (bound && detectsEcbMode(bound)) {
          const pos = sf.getLineAndCharacterOfPosition(firstArg.getStart(sf));
          facts.push(
            makeFact(
              "ecb_mode",
              `ECB mode via variable binding: ${firstArg.text} resolves to "${bound}"`,
              file,
              pos,
              text,
              csprngAvailable,
            ),
          );
        }
      }
    }

    // Track 2 — Static IV via VariableDeclaration.
    if (ts.isVariableDeclaration(node) && node.initializer && ts.isIdentifier(node.name)) {
      const nameLower = node.name.text.toLowerCase();
      if (isIvLikeName(nameLower)) {
        const classification = classifyInitializer(node.initializer, sf);
        if (classification !== null) {
          const pos = sf.getLineAndCharacterOfPosition(node.getStart(sf));
          facts.push(
            makeFact(
              "static_iv",
              `Static ${nameLower}: ${classification}`,
              file,
              pos,
              text,
              csprngAvailable,
            ),
          );
        }
      }
    }

    // Track 3 — Math.random() in crypto context.
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      ts.isIdentifier(node.expression.expression) &&
      node.expression.expression.text === "Math" &&
      node.expression.name.text === "random"
    ) {
      const enclosing = findEnclosingFunctionBody(node);
      if (enclosing !== null) {
        const enclosingText = enclosing.getText(sf);
        if (enclosingBodyHasCryptoContext(enclosingText)) {
          const pos = sf.getLineAndCharacterOfPosition(node.getStart(sf));
          facts.push(
            makeFact(
              "math_random_crypto",
              "Math.random() used in cryptographic context",
              file,
              pos,
              text,
              csprngAvailable,
            ),
          );
        }
      }
    }

    ts.forEachChild(node, visit);
  };

  ts.forEachChild(sf, visit);
}

// ─── Classifiers ───────────────────────────────────────────────────────────

function detectsEcbMode(s: string): boolean {
  const lower = s.toLowerCase();
  if (!lower.includes("ecb")) return false;
  for (const fam of Object.keys(CIPHER_FAMILY_TOKENS)) {
    if (lower.includes(fam)) return true;
  }
  return false;
}

function isIvLikeName(nameLower: string): boolean {
  // Exact or suffix match against IV/nonce/salt.
  for (const token of Object.keys(IV_IDENTIFIER_TOKENS)) {
    if (nameLower === token) return true;
    if (nameLower.endsWith(`_${token}`)) return true;
    if (nameLower.endsWith(token) && nameLower.length <= token.length + 4) return true;
  }
  return false;
}

function classifyInitializer(init: ts.Expression, sf: ts.SourceFile): string | null {
  // Case A: literal string short & looks like zeros/pattern.
  if (ts.isStringLiteral(init)) {
    const text = init.text;
    if (text.length === 0) return null;
    if (isRepeatingCharLiteral(text)) {
      return `literal string "${text}" (repeating character — effective zero IV)`;
    }
    // Short string literal explicitly labelled "abc" / "000" is also static.
    if (text.length <= 4) return `short literal string "${text}"`;
    return null;
  }
  // Case B: Numeric / template literal / array literal.
  if (ts.isNumericLiteral(init)) return `numeric constant ${init.text}`;
  if (ts.isArrayLiteralExpression(init)) {
    const allLiteral = init.elements.every(
      (e) => ts.isNumericLiteral(e) || ts.isStringLiteral(e),
    );
    if (allLiteral) return `constant array of ${init.elements.length} elements`;
  }
  if (ts.isNoSubstitutionTemplateLiteral(init)) {
    if (isRepeatingCharLiteral(init.text)) {
      return `template literal "${init.text}" (repeating character)`;
    }
    return null;
  }
  // Case C: Buffer.alloc(N) — zero-filled buffer (charter lethal edge case #2).
  if (ts.isCallExpression(init)) {
    const callText = init.expression.getText(sf);
    if (callText === "Buffer.alloc" || callText === "Buffer.allocUnsafe") {
      const arg = init.arguments[0];
      if (!arg || ts.isNumericLiteral(arg)) {
        return `Buffer.alloc(${arg ? arg.getText(sf) : "0"}) — zero-filled buffer`;
      }
    }
    // new Uint8Array(N)
    if (callText === "Uint8Array") {
      return "new Uint8Array(N) — zero-filled TypedArray";
    }
  }
  if (ts.isNewExpression(init)) {
    const callText = init.expression.getText(sf);
    if (callText === "Uint8Array") {
      return "new Uint8Array(N) — zero-filled TypedArray";
    }
  }
  return null;
}

function isRepeatingCharLiteral(s: string): boolean {
  if (s.length < 2) return false;
  const first = s.charAt(0);
  for (let i = 1; i < s.length; i++) {
    if (s.charAt(i) !== first) return false;
  }
  return true;
}

function findEnclosingFunctionBody(node: ts.Node): ts.Node | null {
  let cur: ts.Node | undefined = node.parent;
  while (cur) {
    if (
      ts.isFunctionDeclaration(cur) ||
      ts.isFunctionExpression(cur) ||
      ts.isArrowFunction(cur) ||
      ts.isMethodDeclaration(cur)
    ) {
      return cur.body ?? null;
    }
    cur = cur.parent;
  }
  return null;
}

function enclosingBodyHasCryptoContext(text: string): boolean {
  const lower = text.toLowerCase();
  for (const token of Object.keys(CRYPTO_CONTEXT_TOKENS)) {
    if (lower.includes(token)) return true;
  }
  return false;
}

function fileContainsCSPRNG(text: string): boolean {
  const lower = text.toLowerCase();
  for (const fp of Object.keys(CSPRNG_FINGERPRINTS)) {
    if (lower.includes(fp)) return true;
  }
  return false;
}

function collectConstBindings(sf: ts.SourceFile): Map<string, string> {
  const out = new Map<string, string>();
  for (const stmt of sf.statements) {
    if (!ts.isVariableStatement(stmt)) continue;
    for (const decl of stmt.declarationList.declarations) {
      if (!ts.isIdentifier(decl.name)) continue;
      if (!decl.initializer) continue;
      if (ts.isStringLiteral(decl.initializer)) {
        out.set(decl.name.text, decl.initializer.text);
      } else if (ts.isNoSubstitutionTemplateLiteral(decl.initializer)) {
        out.set(decl.name.text, decl.initializer.text);
      }
    }
  }
  return out;
}

// ─── Structural test detection ─────────────────────────────────────────────

function isStructuralTestFile(sf: ts.SourceFile): boolean {
  let hasRunnerImport = false;
  let hasTopLevelSuite = false;
  for (const stmt of sf.statements) {
    if (ts.isImportDeclaration(stmt) && ts.isStringLiteral(stmt.moduleSpecifier)) {
      const spec = stmt.moduleSpecifier.text;
      if (spec === "vitest" || spec === "jest" || spec === "mocha") hasRunnerImport = true;
    }
    if (ts.isExpressionStatement(stmt) && ts.isCallExpression(stmt.expression)) {
      const callee = stmt.expression.expression;
      if (ts.isIdentifier(callee)) {
        const n = callee.text;
        if (n === "describe" || n === "it" || n === "test") hasTopLevelSuite = true;
      }
    }
  }
  // Filename-based heuristic as a secondary signal.
  const name = sf.fileName.toLowerCase();
  const byName = name.endsWith(".test.ts") || name.endsWith(".spec.ts") || name.endsWith(".test.js") || name.endsWith(".spec.js");
  return (hasRunnerImport && hasTopLevelSuite) || byName;
}

// ─── Fact construction ─────────────────────────────────────────────────────

function makeFact(
  variant: P8VariantId,
  description: string,
  file: string,
  pos: ts.LineAndCharacter,
  text: string,
  csprngAvailable: boolean,
): P8Fact {
  const lineNumber = pos.line + 1;
  const col = pos.character + 1;
  const rawLine = text.split("\n")[pos.line] ?? "";
  return {
    variant,
    file,
    line: lineNumber,
    col,
    observed: rawLine.trim().slice(0, 160),
    description,
    location: { kind: "source", file, line: lineNumber, col },
    csprngAvailableNearby: csprngAvailable,
  };
}
