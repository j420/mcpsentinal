/** L15 evidence gathering — AST + token walker. Zero regex. */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  NOTIFICATION_SIGNALS,
  INSTALL_COMMAND_ANCHORS,
  INSTALL_COMMAND_VERBS,
  PIPE_SHELL_TOKENS,
  SHELL_EXECUTORS,
  LEGITIMATE_UPDATE_IDIOMS,
  type UpdateSignal,
} from "./data/update-vocabulary.js";

interface Token {
  readonly value: string;
  readonly start: number;
  readonly end: number;
}

export interface SpoofSite {
  readonly location: Location;
  readonly observed: string;
  readonly notification_desc: string;
  readonly install_evidence: string;
  readonly enclosing_has_legitimate_idiom: boolean;
}

const INSTALL_ANCHORS_SET: ReadonlySet<string> = new Set(INSTALL_COMMAND_ANCHORS);
const INSTALL_VERBS_SET: ReadonlySet<string> = new Set(INSTALL_COMMAND_VERBS);
const PIPE_SHELL_SET: ReadonlySet<string> = new Set(PIPE_SHELL_TOKENS);
const SHELL_EXECUTORS_SET: ReadonlySet<string> = new Set(SHELL_EXECUTORS);
const LEGITIMATE_SET: ReadonlySet<string> = new Set(LEGITIMATE_UPDATE_IDIOMS);

function tokenise(text: string): Token[] {
  const tokens: Token[] = [];
  const n = text.length;
  let i = 0;
  while (i < n) {
    const c = text.charCodeAt(i);
    const isWord =
      (c >= 0x30 && c <= 0x39) ||
      (c >= 0x41 && c <= 0x5a) ||
      (c >= 0x61 && c <= 0x7a) ||
      c === 0x5f || c === 0x2d;
    if (isWord) {
      const start = i;
      while (i < n) {
        const cc = text.charCodeAt(i);
        const ok =
          (cc >= 0x30 && cc <= 0x39) ||
          (cc >= 0x41 && cc <= 0x5a) ||
          (cc >= 0x61 && cc <= 0x7a) ||
          cc === 0x5f || cc === 0x2d;
        if (!ok) break;
        i++;
      }
      tokens.push({ value: text.slice(start, i).toLowerCase(), start, end: i });
    } else {
      i++;
    }
  }
  return tokens;
}

function detectNotification(tokens: readonly Token[]): string | null {
  for (const [, signal] of Object.entries(NOTIFICATION_SIGNALS) as Array<
    [string, UpdateSignal]
  >) {
    for (let i = 0; i < tokens.length; i++) {
      if (!signal.anchor_tokens.includes(tokens[i].value)) continue;
      if (signal.qualifier_tokens.length === 0) return signal.desc;
      const end = Math.min(tokens.length - 1, i + signal.proximity);
      for (let j = i + 1; j <= end; j++) {
        if (signal.qualifier_tokens.includes(tokens[j].value)) return signal.desc;
      }
    }
  }
  return null;
}

function detectInstall(tokens: readonly Token[]): string | null {
  // npm/pnpm/yarn/pip/brew followed by install/add
  for (let i = 0; i < tokens.length - 1; i++) {
    if (INSTALL_ANCHORS_SET.has(tokens[i].value) && INSTALL_VERBS_SET.has(tokens[i + 1].value)) {
      return `${tokens[i].value} ${tokens[i + 1].value}`;
    }
  }
  // curl / wget ... bash / sh (pipe-to-shell)
  let sawPipe = false;
  for (const tok of tokens) {
    if (PIPE_SHELL_SET.has(tok.value)) sawPipe = true;
    if (sawPipe && SHELL_EXECUTORS_SET.has(tok.value)) return `${tok.value} (pipe-to-shell)`;
  }
  return null;
}

function enclosingHasLegitimateIdiom(node: ts.Node, sf: ts.SourceFile): boolean {
  let cur: ts.Node | undefined = node.parent;
  while (cur) {
    if (
      ts.isFunctionDeclaration(cur) ||
      ts.isFunctionExpression(cur) ||
      ts.isArrowFunction(cur) ||
      ts.isMethodDeclaration(cur)
    ) {
      const text = cur.getText(sf).toLowerCase();
      for (const idiom of LEGITIMATE_SET) {
        if (text.includes(idiom)) return true;
      }
      break;
    }
    cur = cur.parent;
  }
  // Also check file-level imports/requires
  const fullText = sf.getFullText().toLowerCase();
  for (const idiom of LEGITIMATE_SET) {
    const marker = `"${idiom}"`;
    if (fullText.includes(marker)) return true;
    const marker2 = `'${idiom}'`;
    if (fullText.includes(marker2)) return true;
  }
  return false;
}

function extractTextFromTemplate(node: ts.TemplateExpression): string {
  let out = node.head.text;
  for (const span of node.templateSpans) {
    out += " ";
    out += span.literal.text;
  }
  return out;
}

export function gatherL15(context: AnalysisContext): SpoofSite[] {
  const out: SpoofSite[] = [];
  const files = context.source_files ?? (context.source_code ? new Map([["scan.ts", context.source_code]]) : new Map());

  for (const [file, text] of files) {
    if (!text) continue;
    let sf: ts.SourceFile;
    try {
      sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
    } catch {
      continue;
    }

    const visit = (node: ts.Node): void => {
      let literalText: string | null = null;
      if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
        literalText = node.text;
      } else if (ts.isTemplateExpression(node)) {
        literalText = extractTextFromTemplate(node);
      }

      if (literalText !== null && literalText.length >= 12) {
        const tokens = tokenise(literalText);
        const notif = detectNotification(tokens);
        const install = detectInstall(tokens);
        if (notif !== null && install !== null) {
          const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
          const legit = enclosingHasLegitimateIdiom(node, sf);
          out.push({
            location: { kind: "source", file, line },
            observed: literalText.slice(0, 160),
            notification_desc: notif,
            install_evidence: install,
            enclosing_has_legitimate_idiom: legit,
          });
        }
      }

      ts.forEachChild(node, visit);
    };

    ts.forEachChild(sf, visit);
  }
  return out;
}
