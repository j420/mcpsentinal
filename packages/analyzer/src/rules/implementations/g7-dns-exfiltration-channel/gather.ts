/**
 * G7 — DNS-Based Data Exfiltration Channel: fact gathering.
 *
 * Structural AST scan. The rule emits a G7Fact for every DNS-resolution
 * call whose hostname argument is NOT a hardcoded string literal. The
 * walker recovers:
 *
 *   - The sink (dns.resolve / dns.lookup / socket.gethostbyname / ...,
 *     or a project-local wrapper whose name contains resolve / lookup /
 *     dns).
 *   - The hostname expression, including any template-literal spans.
 *   - Whether the dynamic portion references a sensitive source
 *     (tainted variable whose name matches SENSITIVE_SOURCE_MARKERS,
 *     OR a direct env / user-parameter / file-content read).
 *   - Whether an encoding wrapper (Buffer.from / btoa / base64.b64encode /
 *     crypto.createHash / .toString("hex")) appears on the path from the
 *     source to the sink — a structural entropy estimate.
 *   - Whether a hostname-allowlist primitive is present in the
 *     enclosing function scope.
 *
 * Uses Shannon entropy on the CONSTANT portion of the hostname
 * template (the attacker-controlled domain suffix — `.attacker.com`
 * is low entropy, but the CONSTRUCTED subdomain can inherit entropy
 * structurally through encoding wrappers). The entropy of the
 * constant portion is recorded on the fact as
 * `constantHostnameEntropy`, consumed by index.ts as a confidence
 * factor.
 *
 * Zero regex literals, zero string arrays > 5. Reuses the shared
 * Shannon entropy analyser at `../../analyzers/entropy.ts`.
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import { shannonEntropy } from "../../analyzers/entropy.js";
import {
  G7_DNS_SINKS,
  G7_DNS_WRAPPER_MARKERS,
  G7_SENSITIVE_SOURCE_MARKERS,
  G7_ENCODING_WRAPPERS,
  G7_ALLOWLIST_MARKERS,
  type DnsSink,
  type DnsWrapperMarker,
  type SensitiveSourceMarker,
  type EncodingWrapper,
  type AllowlistMarker,
} from "./data/config.js";

// ─── Fact types emitted to index.ts ──────────────────────────────────────

export interface G7Fact {
  readonly sink: DnsSink | DnsWrapperMarker;
  readonly sinkKind: "canonical" | "wrapper-heuristic";
  readonly sinkLocation: Location;
  readonly sinkObserved: string;

  /** Hostname expression — the dynamic subdomain construction. */
  readonly hostnameExpression: string;
  readonly hostnameLocation: Location;

  /**
   * The dynamic portion of the hostname: template-literal spans,
   * identifiers, call expressions. Each a propagation hop.
   */
  readonly dynamicHops: ReadonlyArray<{
    kind: "template-embed" | "concatenation" | "identifier-ref" | "wrapper-call";
    location: Location;
    observed: string;
  }>;

  /** Sensitive-source markers whose identifiers appear anywhere on the hop chain. */
  readonly sensitiveSourceMatches: readonly SensitiveSourceMarker[];

  /** Encoding wrappers observed on the hop chain. */
  readonly encodingWrappers: readonly EncodingWrapper[];

  /** Allowlist primitive in the enclosing function scope (if any). */
  readonly allowlist: AllowlistMarker | null;
  readonly allowlistLocation: Location | null;

  /** Shannon entropy of the CONSTANT portion of the hostname template. */
  readonly constantHostnameEntropy: number;
  /** Constant portion that was measured (capped). */
  readonly constantHostnameText: string;
}

export interface G7GatherResult {
  readonly mode: "absent" | "test-file" | "facts";
  readonly file: string;
  readonly facts: readonly G7Fact[];
}

// ─── Gather ──────────────────────────────────────────────────────────────

const SYNTHETIC_FILE = "<source>";

export function gatherG7(context: AnalysisContext): G7GatherResult {
  const source = context.source_code;
  if (!source || source.length === 0) {
    return { mode: "absent", file: SYNTHETIC_FILE, facts: [] };
  }
  if (isTestFileShape(source)) {
    return { mode: "test-file", file: SYNTHETIC_FILE, facts: [] };
  }

  const sf = ts.createSourceFile(SYNTHETIC_FILE, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  const facts: G7Fact[] = [];

  ts.forEachChild(sf, function visit(node) {
    if (ts.isCallExpression(node)) {
      const fact = analyzeCall(node, sf);
      if (fact) facts.push(fact);
    }
    ts.forEachChild(node, visit);
  });

  return {
    mode: facts.length > 0 ? "facts" : "absent",
    file: SYNTHETIC_FILE,
    facts,
  };
}

// ─── Test-file detection ─────────────────────────────────────────────────

function isTestFileShape(source: string): boolean {
  return (
    source.includes("__tests__") ||
    source.includes(".test.") ||
    source.includes(".spec.") ||
    source.includes("from \"vitest\"") ||
    source.includes("describe(")
  );
}

// ─── Call analysis ───────────────────────────────────────────────────────

function analyzeCall(node: ts.CallExpression, sf: ts.SourceFile): G7Fact | null {
  const callee = renderCallee(node.expression);
  const canonical = matchCanonicalSink(callee);
  const wrapper = canonical ? null : matchWrapperMarker(callee);
  if (!canonical && !wrapper) return null;
  const argIdx = canonical ? canonical.hostnameArgIdx : 0;
  const hostnameArg = node.arguments[argIdx];
  if (!hostnameArg) return null;

  // Skip hardcoded string-literal hostnames — the classic TN shape
  // (`dns.resolve("api.example.com")`).
  if (ts.isStringLiteral(hostnameArg) || ts.isNoSubstitutionTemplateLiteral(hostnameArg)) {
    return null;
  }

  const dynamicHops = collectDynamicHops(hostnameArg, sf);
  if (dynamicHops.length === 0) return null;

  const hopText = dynamicHops.map((h) => h.observed).join(" ").toLowerCase();
  const sensitive = collectSensitiveMarkers(hopText);
  const encodings = collectEncodingWrappers(hostnameArg, sf);
  const enclosing = findEnclosingFunction(node);
  const allowlistHit = findAllowlistInScope(enclosing, sf);

  const { entropy, text: constantText } = computeConstantEntropy(hostnameArg, sf);

  const nodeStart = sf.getLineAndCharacterOfPosition(node.getStart(sf));
  const hostStart = sf.getLineAndCharacterOfPosition(hostnameArg.getStart(sf));

  return {
    sink: canonical ?? wrapper!,
    sinkKind: canonical ? "canonical" : "wrapper-heuristic",
    sinkLocation: { kind: "source", file: sf.fileName, line: nodeStart.line + 1, col: nodeStart.character + 1 },
    sinkObserved: node.getText(sf).slice(0, 160),
    hostnameExpression: hostnameArg.getText(sf).slice(0, 160),
    hostnameLocation: { kind: "source", file: sf.fileName, line: hostStart.line + 1, col: hostStart.character + 1 },
    dynamicHops,
    sensitiveSourceMatches: sensitive,
    encodingWrappers: encodings,
    allowlist: allowlistHit?.marker ?? null,
    allowlistLocation: allowlistHit?.location ?? null,
    constantHostnameEntropy: entropy,
    constantHostnameText: constantText,
  };
}

function matchCanonicalSink(callee: string): DnsSink | null {
  for (const sink of G7_DNS_SINKS) {
    if (sink.name === callee) return sink;
  }
  return null;
}

function matchWrapperMarker(callee: string): DnsWrapperMarker | null {
  const lower = callee.toLowerCase();
  for (const marker of G7_DNS_WRAPPER_MARKERS) {
    if (lower.includes(marker.token.toLowerCase())) return marker;
  }
  return null;
}

// ─── Dynamic-portion extraction ──────────────────────────────────────────

function collectDynamicHops(
  hostname: ts.Expression,
  sf: ts.SourceFile,
): Array<{ kind: "template-embed" | "concatenation" | "identifier-ref" | "wrapper-call"; location: Location; observed: string }> {
  const out: Array<{ kind: "template-embed" | "concatenation" | "identifier-ref" | "wrapper-call"; location: Location; observed: string }> = [];

  function visit(node: ts.Node) {
    if (ts.isTemplateExpression(node)) {
      for (const span of node.templateSpans) {
        const start = sf.getLineAndCharacterOfPosition(span.getStart(sf));
        out.push({
          kind: "template-embed",
          location: { kind: "source", file: sf.fileName, line: start.line + 1, col: start.character + 1 },
          observed: span.expression.getText(sf).slice(0, 80),
        });
        visit(span.expression);
      }
      return;
    }
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      // Record the non-literal operands.
      for (const side of [node.left, node.right]) {
        if (!ts.isStringLiteral(side) && !ts.isNoSubstitutionTemplateLiteral(side)) {
          const start = sf.getLineAndCharacterOfPosition(side.getStart(sf));
          out.push({
            kind: "concatenation",
            location: { kind: "source", file: sf.fileName, line: start.line + 1, col: start.character + 1 },
            observed: side.getText(sf).slice(0, 80),
          });
          visit(side);
        }
      }
      return;
    }
    if (ts.isIdentifier(node)) {
      const start = sf.getLineAndCharacterOfPosition(node.getStart(sf));
      out.push({
        kind: "identifier-ref",
        location: { kind: "source", file: sf.fileName, line: start.line + 1, col: start.character + 1 },
        observed: node.text,
      });
      return;
    }
    if (ts.isCallExpression(node)) {
      const start = sf.getLineAndCharacterOfPosition(node.getStart(sf));
      out.push({
        kind: "wrapper-call",
        location: { kind: "source", file: sf.fileName, line: start.line + 1, col: start.character + 1 },
        observed: node.getText(sf).slice(0, 80),
      });
      // Recurse into arguments.
      for (const arg of node.arguments) visit(arg);
      return;
    }
    ts.forEachChild(node, visit);
  }

  visit(hostname);
  return out;
}

function collectSensitiveMarkers(hopText: string): SensitiveSourceMarker[] {
  const out: SensitiveSourceMarker[] = [];
  for (const marker of G7_SENSITIVE_SOURCE_MARKERS) {
    if (hopText.includes(marker.token.toLowerCase())) out.push(marker);
  }
  return out;
}

function collectEncodingWrappers(
  hostname: ts.Expression,
  sf: ts.SourceFile,
): EncodingWrapper[] {
  const hostText = hostname.getText(sf);
  const out: EncodingWrapper[] = [];
  for (const wrap of G7_ENCODING_WRAPPERS) {
    if (hostText.includes(wrap.name)) out.push(wrap);
  }
  return out;
}

// ─── Allowlist detection (enclosing scope) ───────────────────────────────

function findAllowlistInScope(
  scope: ts.Node | null,
  sf: ts.SourceFile,
): { marker: AllowlistMarker; location: Location } | null {
  if (!scope) return null;
  const bodyText = scope.getText(sf);
  for (const marker of G7_ALLOWLIST_MARKERS) {
    if (bodyText.includes(marker.name)) {
      const start = sf.getLineAndCharacterOfPosition(scope.getStart(sf));
      return {
        marker,
        location: {
          kind: "source",
          file: sf.fileName,
          line: start.line + 1,
          col: start.character + 1,
        },
      };
    }
  }
  return null;
}

function findEnclosingFunction(node: ts.Node): ts.Node | null {
  let n: ts.Node | undefined = node.parent;
  while (n) {
    if (
      ts.isFunctionDeclaration(n) ||
      ts.isFunctionExpression(n) ||
      ts.isArrowFunction(n) ||
      ts.isMethodDeclaration(n) ||
      ts.isSourceFile(n)
    ) {
      return n;
    }
    n = n.parent;
  }
  return null;
}

// ─── Entropy of the constant portion ─────────────────────────────────────

function computeConstantEntropy(
  hostname: ts.Expression,
  sf: ts.SourceFile,
): { entropy: number; text: string } {
  // Collect the CONSTANT template-literal chunks — the non-interpolated
  // head + middle + tail that make up the attacker domain suffix.
  if (!ts.isTemplateExpression(hostname)) {
    // Plain binary concat or identifier — no constant to measure.
    return { entropy: 0, text: "" };
  }
  const parts: string[] = [hostname.head.text];
  for (const span of hostname.templateSpans) parts.push(span.literal.text);
  const text = parts.join("");
  const sample = text.slice(0, 160);
  return { entropy: shannonEntropy(sample), text: sample };
}

// ─── AST helpers ─────────────────────────────────────────────────────────

function renderCallee(expr: ts.Node): string {
  if (ts.isIdentifier(expr)) return expr.text;
  if (ts.isPropertyAccessExpression(expr)) {
    return `${renderCallee(expr.expression)}.${expr.name.text}`;
  }
  return "";
}
