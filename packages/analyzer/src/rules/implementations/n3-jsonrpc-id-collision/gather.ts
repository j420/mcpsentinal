/**
 * N3 — Deterministic fact gathering for JSON-RPC request id collision.
 *
 * Walk the AST looking for assignments to id-target identifiers where the
 * right-hand side is (a) a counter increment expression, (b) a timestamp
 * source, or (c) a plain integer literal. If any such assignment exists AND
 * the enclosing function contains no cryptographic generator call, emit a
 * fact.
 */

import ts from "typescript";
import {
  REQUEST_ID_IDENTIFIERS,
  CRYPTO_GENERATORS,
  TIMESTAMP_SOURCES,
} from "./data/id-vocabulary.js";

export interface SourceLocation {
  readonly kind: "source_code_line";
  readonly line: number;
  readonly column: number;
  readonly snippet: string;
  readonly enclosing_function: string | null;
}

export type GeneratorKind = "counter-increment" | "timestamp" | "integer-literal";

export interface IdAssignment {
  readonly location: SourceLocation;
  readonly target_identifier: string;
  readonly rhs_expression: string;
  readonly generator_kind: GeneratorKind;
  readonly crypto_generator_in_scope: boolean;
}

export interface GatheredFacts {
  readonly facts: IdAssignment[];
  readonly parse_succeeded: boolean;
}

function normaliseIdentifier(name: string): string {
  return name.replace(/^_+/, "").toLowerCase();
}

function isIdTarget(name: string): boolean {
  const normalised = normaliseIdentifier(name);
  return Object.prototype.hasOwnProperty.call(REQUEST_ID_IDENTIFIERS, normalised);
}

/** Classify the right-hand side expression into one of the predictable kinds. */
function classifyRhs(expr: ts.Expression, sf: ts.SourceFile): GeneratorKind | null {
  // Counter increment / decrement: ++x, x++, x = x + 1, x += 1, ++this.counter, etc.
  if (ts.isPrefixUnaryExpression(expr) && (expr.operator === ts.SyntaxKind.PlusPlusToken || expr.operator === ts.SyntaxKind.MinusMinusToken)) {
    return "counter-increment";
  }
  if (ts.isPostfixUnaryExpression(expr) && (expr.operator === ts.SyntaxKind.PlusPlusToken || expr.operator === ts.SyntaxKind.MinusMinusToken)) {
    return "counter-increment";
  }
  if (ts.isBinaryExpression(expr)) {
    const opKind = expr.operatorToken.kind;
    if (opKind === ts.SyntaxKind.PlusEqualsToken || opKind === ts.SyntaxKind.MinusEqualsToken) {
      return "counter-increment";
    }
    if (opKind === ts.SyntaxKind.PlusToken || opKind === ts.SyntaxKind.MinusToken) {
      const rightText = expr.right.getText(sf);
      if (/^[0-9]+$/.test(rightText)) return "counter-increment";
      const leftText = expr.left.getText(sf);
      if (/^[0-9]+$/.test(leftText)) return "counter-increment";
    }
  }

  // Timestamp sources.
  const text = expr.getText(sf);
  for (const key of Object.keys(TIMESTAMP_SOURCES)) {
    if (text.includes(key)) return "timestamp";
  }

  // Plain integer literal or identifier referencing a known counter variable.
  if (ts.isNumericLiteral(expr)) return "integer-literal";

  // Identifier reference matching a counter-named variable.
  if (ts.isIdentifier(expr)) {
    const normalised = expr.text.toLowerCase();
    if (normalised === "counter" || normalised.endsWith("counter") || normalised === "seq" || normalised.endsWith("seq")) {
      return "counter-increment";
    }
  }

  return null;
}

function enclosingFunction(node: ts.Node): ts.Node | null {
  let cur: ts.Node | undefined = node.parent;
  while (cur) {
    if (
      ts.isFunctionDeclaration(cur) ||
      ts.isFunctionExpression(cur) ||
      ts.isArrowFunction(cur) ||
      ts.isMethodDeclaration(cur) ||
      ts.isClassDeclaration(cur) ||
      ts.isConstructorDeclaration(cur)
    ) {
      return cur;
    }
    cur = cur.parent;
  }
  return null;
}

function cryptoGeneratorInScope(scopeText: string): boolean {
  for (const key of Object.keys(CRYPTO_GENERATORS)) {
    if (scopeText.includes(key)) return true;
  }
  // Look for `randomUUID(` or `uuid(` call syntax that wasn't captured above.
  if (scopeText.includes("randomUUID(")) return true;
  if (scopeText.includes("uuid(")) return true;
  if (scopeText.includes("nanoid(")) return true;
  return false;
}

function makeLocation(node: ts.Node, sf: ts.SourceFile, source: string): SourceLocation {
  const start = node.getStart(sf);
  const pos = sf.getLineAndCharacterOfPosition(start);
  const line = pos.line + 1;
  const column = pos.character + 1;
  const lineText = source.split("\n")[line - 1] ?? "";
  const encl = enclosingFunction(node);
  const enclName =
    encl && ts.isFunctionDeclaration(encl) && encl.name
      ? encl.name.getText(sf)
      : encl && ts.isMethodDeclaration(encl) && encl.name
      ? encl.name.getText(sf)
      : null;
  return {
    kind: "source_code_line",
    line,
    column,
    snippet: lineText.trim().slice(0, 200),
    enclosing_function: enclName,
  };
}

export function gather(source: string): GatheredFacts {
  const facts: IdAssignment[] = [];

  let sf: ts.SourceFile;
  try {
    sf = ts.createSourceFile("scan.ts", source, ts.ScriptTarget.Latest, true);
  } catch {
    return { facts, parse_succeeded: false };
  }

  const addFact = (
    node: ts.Node,
    targetIdentifier: string,
    rhs: ts.Expression,
  ): void => {
    const kind = classifyRhs(rhs, sf);
    if (!kind) return;
    const encl = enclosingFunction(node);
    const scopeText = encl ? encl.getText(sf) : source;
    const cryptoPresent = cryptoGeneratorInScope(scopeText);
    if (cryptoPresent) return;
    facts.push({
      location: makeLocation(node, sf, source),
      target_identifier: targetIdentifier,
      rhs_expression: rhs.getText(sf).slice(0, 80),
      generator_kind: kind,
      crypto_generator_in_scope: cryptoPresent,
    });
  };

  const visit = (node: ts.Node): void => {
    // Variable declaration: let requestId = ++counter
    if (ts.isVariableDeclaration(node) && node.initializer) {
      const name = node.name.getText(sf);
      if (isIdTarget(name)) {
        addFact(node, name, node.initializer);
      }
    }

    // Class property: requestId = ++this.counter  or  requestId: number = 0;
    if (ts.isPropertyDeclaration(node) && node.name && node.initializer) {
      const name = node.name.getText(sf);
      if (isIdTarget(name)) {
        addFact(node, name, node.initializer);
      }
    }

    // Assignment expression: this.requestId = this.counter++ ;  payload.id = n;
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      // Accept left-hand side like `obj.id`, `this.requestId`, `payload.id`.
      let leftName: string | null = null;
      if (ts.isPropertyAccessExpression(node.left)) {
        leftName = node.left.name.getText(sf);
      } else if (ts.isIdentifier(node.left)) {
        leftName = node.left.text;
      } else if (ts.isElementAccessExpression(node.left)) {
        const arg = node.left.argumentExpression;
        if (arg && ts.isStringLiteral(arg)) leftName = arg.text;
      }
      if (leftName) {
        // Handle the literal property name "id" when the owning object is a
        // JSON-RPC message payload (variable name contains request/payload/msg).
        const isPlainId = leftName.toLowerCase() === "id";
        const lhsOwnerText = node.left.getText(sf).toLowerCase();
        const ownerLooksLikeRpc = /(request|payload|msg|message|rpc|req)/.test(lhsOwnerText);
        if (isIdTarget(leftName) || (isPlainId && ownerLooksLikeRpc)) {
          addFact(node, leftName, node.right);
        }
      }
    }

    // Object literal entry: { id: Date.now() } inside a JSON-RPC-shaped literal.
    if (ts.isPropertyAssignment(node) && ts.isIdentifier(node.name)) {
      const propName = node.name.text;
      if (propName === "id") {
        // Only consider the property when the surrounding object literal has
        // a sibling "jsonrpc" or "method" or "params" field — i.e. it's
        // structurally a JSON-RPC request.
        const parent = node.parent;
        if (parent && ts.isObjectLiteralExpression(parent)) {
          const hasRpcSibling = parent.properties.some((p) => {
            if (!ts.isPropertyAssignment(p) || !ts.isIdentifier(p.name)) return false;
            const n = p.name.text;
            return n === "jsonrpc" || n === "method" || n === "params";
          });
          if (hasRpcSibling) {
            addFact(node, "id", node.initializer);
          }
        }
      }
    }

    ts.forEachChild(node, visit);
  };

  ts.forEachChild(sf, visit);
  return { facts, parse_succeeded: true };
}
