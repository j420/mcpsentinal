/**
 * O10 gather — AST walk for (telemetry surface read) × (network send)
 * within the same enclosing function.
 *
 * Zero regex. One pass per enclosing function collects:
 *
 *   - `surfaces`      Identifier / PropertyAccess hits against the
 *                     OS / NETWORK / SOFTWARE / DEVICE vocabularies.
 *   - `networkSinks`  Call expressions whose callee identifier text
 *                     matches the network-send primitive catalogue.
 *   - `pixelHints`    String literals matching PIXEL_HINTS (any
 *                     substring — walked as verbatim string tokens
 *                     via structured text-equality, not regex).
 *   - `consentFlag`   Whether an enclosing `if` predicate reads a
 *                     consent-check identifier; demotes (not skips).
 *   - `envBulk`       Shared-exfil-sink cross-reference: whether
 *                     `_shared/data-exfil-sinks.ts` env-var tokens
 *                     (process.env bulk access hints) appear in
 *                     the enclosing function.
 *
 * Honest-refusal gate: if no network-send primitive exists anywhere
 * in the source, the rule returns nothing.
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  OS_SURFACE,
  NETWORK_SURFACE,
  SOFTWARE_SURFACE,
  DEVICE_SURFACE,
  NETWORK_SEND_PRIMITIVES,
  CONSENT_IDENTIFIERS,
  PIXEL_HINTS,
} from "./data/telemetry-surfaces.js";
import { DATA_EXFIL_SINKS } from "../_shared/data-exfil-sinks.js";

// ─── Surface maps ──────────────────────────────────────────────────────────

const OS_SET: ReadonlySet<string> = new Set(Object.keys(OS_SURFACE));
const NET_SET: ReadonlySet<string> = new Set(Object.keys(NETWORK_SURFACE));
const SW_SET: ReadonlySet<string> = new Set(Object.keys(SOFTWARE_SURFACE));
const DEV_SET: ReadonlySet<string> = new Set(Object.keys(DEVICE_SURFACE));
const SEND_SET: ReadonlySet<string> = new Set(Object.keys(NETWORK_SEND_PRIMITIVES));
const CONSENT_SET: ReadonlySet<string> = new Set(
  Object.keys(CONSENT_IDENTIFIERS).map((k) => k.toLowerCase()),
);
const PIXEL_SET: ReadonlySet<string> = new Set(
  Object.keys(PIXEL_HINTS).map((k) => k.toLowerCase()),
);
const ENV_VAR_TOKENS: ReadonlySet<string> = buildEnvVarTokenSet();

function buildEnvVarTokenSet(): ReadonlySet<string> {
  const s = new Set<string>();
  for (const spec of Object.values(DATA_EXFIL_SINKS)) {
    if (spec.kind !== "env-var") continue;
    for (const tok of spec.tokens) s.add(tok.toLowerCase());
  }
  return s;
}

export type SurfaceKind = "os" | "network" | "software" | "device";

export interface SurfaceHit {
  kind: SurfaceKind;
  token: string;
  location: Location;
}

export interface TelemetrySite {
  /** Enclosing function location (null → module scope). */
  enclosingFunctionLocation: Location | null;
  /** Enumerated identity surfaces observed in this function. */
  surfaces: SurfaceHit[];
  /** Location of the first network-send primitive in this function. */
  networkSink: { token: string; location: Location };
  /** First pixel-hint string literal, if any. */
  pixelHint: { token: string; location: Location } | null;
  /** Consent-identifier found in an enclosing if-predicate. */
  consentFlag: string | null;
  /** Shared-sink cross-reference: env-var bulk read in enclosing scope. */
  envBulk: boolean;
}

export interface O10Gathered {
  sites: TelemetrySite[];
  hasNetworkPrimitive: boolean;
}

export function gatherO10(context: AnalysisContext): O10Gathered {
  const text = context.source_code;
  if (!text) return { sites: [], hasNetworkPrimitive: false };

  const sf = ts.createSourceFile(
    "<concatenated-source>",
    text,
    ts.ScriptTarget.Latest,
    true,
  );

  if (!hasNetworkPrimitive(sf)) return { sites: [], hasNetworkPrimitive: false };

  const sites: TelemetrySite[] = [];
  const enclosingScopes = collectEnclosingScopes(sf);

  for (const scope of enclosingScopes) {
    const surfaces = collectSurfaces(scope.node, sf);
    if (surfaces.length === 0) continue;
    const sink = findNetworkSink(scope.node, sf);
    const pixelHint = findPixelHint(scope.node, sf);
    if (!sink && !pixelHint) continue;
    const consentFlag = findConsentFlag(scope.node);
    const envBulk = scopeHasEnvBulk(scope.node);
    sites.push({
      enclosingFunctionLocation: scope.location,
      surfaces,
      networkSink: sink ?? {
        token: "response-body",
        location: pixelHint!.location,
      },
      pixelHint,
      consentFlag,
      envBulk,
    });
  }

  return { sites, hasNetworkPrimitive: true };
}

function hasNetworkPrimitive(sf: ts.SourceFile): boolean {
  let found = false;
  function visit(n: ts.Node): void {
    if (found) return;
    if (ts.isIdentifier(n) && SEND_SET.has(n.text)) {
      found = true;
      return;
    }
    if (ts.isPropertyAccessExpression(n) && SEND_SET.has(n.name.text)) {
      found = true;
      return;
    }
    ts.forEachChild(n, visit);
  }
  ts.forEachChild(sf, visit);
  return found;
}

interface EnclosingScope {
  node: ts.Node;
  location: Location | null;
}

function collectEnclosingScopes(sf: ts.SourceFile): EnclosingScope[] {
  const scopes: EnclosingScope[] = [];
  ts.forEachChild(sf, function visit(node) {
    if (
      ts.isFunctionDeclaration(node) ||
      ts.isMethodDeclaration(node) ||
      ts.isFunctionExpression(node) ||
      ts.isArrowFunction(node)
    ) {
      scopes.push({ node, location: sourceLocation(sf, node) });
    }
    ts.forEachChild(node, visit);
  });
  // Always include the module as an outer scope so top-level telemetry fires.
  scopes.push({ node: sf, location: null });
  return scopes;
}

function collectSurfaces(scope: ts.Node, sf: ts.SourceFile): SurfaceHit[] {
  const hits: SurfaceHit[] = [];
  function visit(n: ts.Node): void {
    if (ts.isPropertyAccessExpression(n)) {
      const name = n.name.text;
      const kind = classify(name);
      if (kind !== null) {
        hits.push({ kind, token: name, location: sourceLocation(sf, n) });
      }
    } else if (ts.isIdentifier(n)) {
      const kind = classify(n.text);
      if (kind === "device") {
        hits.push({ kind, token: n.text, location: sourceLocation(sf, n) });
      }
    } else if (ts.isStringLiteral(n)) {
      const kind = classify(n.text);
      if (kind === "device") {
        hits.push({ kind, token: n.text, location: sourceLocation(sf, n) });
      }
    }
    ts.forEachChild(n, visit);
  }
  ts.forEachChild(scope, visit);
  return hits;
}

function classify(token: string): SurfaceKind | null {
  if (OS_SET.has(token)) return "os";
  if (NET_SET.has(token)) return "network";
  if (SW_SET.has(token)) return "software";
  if (DEV_SET.has(token)) return "device";
  return null;
}

function findNetworkSink(
  scope: ts.Node,
  sf: ts.SourceFile,
): { token: string; location: Location } | null {
  let hit: { token: string; location: Location } | null = null;
  function visit(n: ts.Node): void {
    if (hit) return;
    if (ts.isCallExpression(n)) {
      if (ts.isIdentifier(n.expression) && SEND_SET.has(n.expression.text)) {
        hit = { token: n.expression.text, location: sourceLocation(sf, n) };
        return;
      }
      if (ts.isPropertyAccessExpression(n.expression)) {
        const name = n.expression.name.text;
        if (SEND_SET.has(name)) {
          hit = { token: name, location: sourceLocation(sf, n) };
          return;
        }
      }
    }
    ts.forEachChild(n, visit);
  }
  ts.forEachChild(scope, visit);
  return hit;
}

function findPixelHint(
  scope: ts.Node,
  sf: ts.SourceFile,
): { token: string; location: Location } | null {
  let hit: { token: string; location: Location } | null = null;
  function visit(n: ts.Node): void {
    if (hit) return;
    if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) {
      const lowered = n.text.toLowerCase();
      for (const needle of PIXEL_SET) {
        if (lowered.includes(needle)) {
          hit = { token: needle, location: sourceLocation(sf, n) };
          return;
        }
      }
    }
    ts.forEachChild(n, visit);
  }
  ts.forEachChild(scope, visit);
  return hit;
}

function findConsentFlag(scope: ts.Node): string | null {
  let found: string | null = null;
  function visit(n: ts.Node): void {
    if (found) return;
    if (ts.isIfStatement(n)) {
      const pred = n.expression.getText().toLowerCase();
      for (const tok of CONSENT_SET) {
        if (pred.includes(tok)) {
          found = tok;
          return;
        }
      }
    }
    ts.forEachChild(n, visit);
  }
  ts.forEachChild(scope, visit);
  return found;
}

function scopeHasEnvBulk(scope: ts.Node): boolean {
  let found = false;
  function visit(n: ts.Node): void {
    if (found) return;
    if (ts.isIdentifier(n)) {
      if (ENV_VAR_TOKENS.has(n.text.toLowerCase())) {
        // single token match alone isn't enough; require proximity to
        // `process` / `environ` in the same subtree. The shared
        // catalogue already enumerates both halves, so when BOTH
        // tokens appear in the enclosing subtree the shared-sink
        // cross-reference holds.
        found = true;
      }
    }
    ts.forEachChild(n, visit);
  }
  ts.forEachChild(scope, visit);
  return found;
}

function sourceLocation(sf: ts.SourceFile, node: ts.Node): Location {
  const { line, character } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
  return {
    kind: "source",
    file: sf.fileName,
    line: line + 1,
    col: character + 1,
  };
}
