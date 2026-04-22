/** M7 gather — AST only; zero regex. */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  CONVERSATION_STATE_TOKENS,
  CONVERSATION_STATE_TOKENS_EXTRA,
  MUTATION_METHOD_NAMES,
  MUTATION_METHOD_NAMES_EXTRA,
  READ_ONLY_METHOD_NAMES,
} from "./data/state-vocabulary.js";

const STATE_SET: ReadonlySet<string> = new Set(
  [...CONVERSATION_STATE_TOKENS, ...CONVERSATION_STATE_TOKENS_EXTRA].map((s) => s.toLowerCase()),
);
const MUTATION_SET: ReadonlySet<string> = new Set([
  ...MUTATION_METHOD_NAMES,
  ...MUTATION_METHOD_NAMES_EXTRA,
]);
const READ_ONLY_SET: ReadonlySet<string> = new Set(READ_ONLY_METHOD_NAMES);

export interface InjectionSite {
  readonly location: Location;
  readonly kind: "mutation-call" | "direct-assignment";
  readonly observed: string;
  readonly target_expr: string;
  readonly method: string;
}


const ASSIGNABLE_TAILS: ReadonlySet<string> = new Set([
  "messages",
  "history",
  "turns",
  "context",
  "memory",
]);

function textHasAssignableTail(text: string): boolean {
  const lower = text.toLowerCase();
  for (const t of ASSIGNABLE_TAILS) if (lower.includes(t)) return true;
  return false;
}

function textContainsStateToken(text: string): boolean {
  const lower = text.toLowerCase();
  for (const t of STATE_SET) if (lower.includes(t)) return true;
  return false;
}

export function gatherM7(context: AnalysisContext): InjectionSite[] {
  const out: InjectionSite[] = [];
  const files = context.source_files ?? (context.source_code ? new Map([["scan.ts", context.source_code]]) : new Map());

  for (const [file, text] of files) {
    if (!text) continue;
    let sf: ts.SourceFile;
    try {
      sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
    } catch {
      continue;
    }

    // First pass: collect one-hop alias bindings: `const X = <expr-with-state-token>`
    const aliasTargets = new Set<string>();
    const aliasVisit = (n: ts.Node): void => {
      if (ts.isVariableDeclaration(n) && n.initializer && ts.isIdentifier(n.name)) {
        const initText = n.initializer.getText(sf);
        if (textContainsStateToken(initText)) {
          aliasTargets.add(n.name.text);
        }
      }
      ts.forEachChild(n, aliasVisit);
    };
    ts.forEachChild(sf, aliasVisit);

    const visit = (node: ts.Node): void => {
      // Mutation call: conversation.history.push(...) OR alias.push(...)
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
        const method = node.expression.name.text;
        if (MUTATION_SET.has(method) && !READ_ONLY_SET.has(method)) {
          const receiverExpr = node.expression.expression;
          const receiver = receiverExpr.getText(sf);
          const isAlias = ts.isIdentifier(receiverExpr) && aliasTargets.has(receiverExpr.text);
          if (textContainsStateToken(receiver) || isAlias) {
            const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
            out.push({
              location: { kind: "source", file, line },
              kind: "mutation-call",
              observed: text.split("\n")[line - 1]?.trim().slice(0, 120) ?? "",
              target_expr: receiver,
              method,
            });
          }
        }
      }
      // Direct assignment: context.messages = [...]
      if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
        const left = node.left.getText(sf);
        if (textContainsStateToken(left) && textHasAssignableTail(left)) {
          const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
          out.push({
            location: { kind: "source", file, line },
            kind: "direct-assignment",
            observed: text.split("\n")[line - 1]?.trim().slice(0, 120) ?? "",
            target_expr: left,
            method: "=",
          });
        }
      }
      ts.forEachChild(node, visit);
    };

    ts.forEachChild(sf, visit);
  }
  return out;
}
