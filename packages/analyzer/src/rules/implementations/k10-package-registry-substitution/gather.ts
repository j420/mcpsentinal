/**
 * K10 — Package Registry Substitution: fact gatherer.
 *
 * Three input shapes:
 *
 *   1. .npmrc / pip.conf / go.env files: key=value lines.
 *   2. pyproject.toml: [[tool.poetry.source]] or [tool.pip.index-url].
 *      Parsed as simple line scan looking for index-url = "..." or
 *      url = "..." inside [[tool.poetry.source]].
 *   3. Source code that sets env vars (export NPM_CONFIG_REGISTRY=..., process.env...).
 *
 * Zero regex literals. Structured Location on every fact.
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  ENTERPRISE_MIRROR_SUBSTRINGS,
  REGISTRY_CONFIG_FILES,
  REGISTRY_CONFIG_KEYS,
  TRUSTED_REGISTRY_HOSTS,
  type Ecosystem,
} from "./data/registry-vocabulary.js";

const TRUSTED_HOSTS: ReadonlyMap<string, Ecosystem> = new Map(
  Object.entries(TRUSTED_REGISTRY_HOSTS),
);
const ENTERPRISE_SUBSTRINGS: ReadonlySet<string> = new Set(
  Object.keys(ENTERPRISE_MIRROR_SUBSTRINGS),
);
const CONFIG_KEYS: ReadonlyMap<string, Ecosystem> = new Map(
  Object.entries(REGISTRY_CONFIG_KEYS),
);
const CONFIG_FILES: ReadonlyMap<string, Ecosystem> = new Map(
  Object.entries(REGISTRY_CONFIG_FILES),
);

// ─── Public types ──────────────────────────────────────────────────────────

export type K10Classification = "trusted" | "enterprise-mirror" | "untrusted-external";

export interface K10Fact {
  classification: K10Classification;
  ecosystem: Ecosystem;
  url: string;
  httpsOnly: boolean;
  location: Location;
  observed: string;
  /** Line/column context in the source (for rendering the finding). */
  fileLabel: string;
  /** Whether a scope limiter (@scope:registry) was present for this URL. */
  scoped: boolean;
  /** Whether an integrity-hash mitigation was observed for this ecosystem. */
  integrityHashPresent: boolean;
}

export interface K10GatherResult {
  isTestFile: boolean;
  facts: K10Fact[];
}

// ─── Entry point ───────────────────────────────────────────────────────────

export function gatherK10(context: AnalysisContext): K10GatherResult {
  const facts: K10Fact[] = [];
  const integrityPresent = detectIntegrity(context);

  if (context.source_files && context.source_files.size > 0) {
    for (const [path, text] of context.source_files) {
      if (path.includes("node_modules")) continue;
      if (isTestFileName(path)) continue;
      const ecosystem = classifyFilename(path);
      if (ecosystem !== null) {
        facts.push(...scanConfigFile(path, text, ecosystem, integrityPresent));
      }
    }
  }

  if (context.source_code) {
    const file = firstFileName(context.source_files) ?? "<source>";
    if (!isTestFileName(file)) {
      facts.push(...scanSourceCode(file, context.source_code, integrityPresent));
    }
  }

  return { isTestFile: false, facts };
}

// ─── Config-file scan ──────────────────────────────────────────────────────

function scanConfigFile(
  path: string,
  text: string,
  ecosystem: Ecosystem,
  integrityPresent: boolean,
): K10Fact[] {
  const out: K10Fact[] = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (trimmed.length === 0 || trimmed.startsWith("#") || trimmed.startsWith(";")) continue;

    // Key=value shape with optional whitespace and optional quotes.
    const parsed = parseKeyValue(trimmed);
    if (parsed === null) continue;
    const { key, value, scoped } = parsed;

    // GOPROXY may be a comma-separated list.
    const urlCandidates = key === "GOPROXY" ? value.split(",") : [value];
    for (const candidate of urlCandidates) {
      const url = candidate.trim();
      if (!url.startsWith("http://") && !url.startsWith("https://")) continue;

      const keyEcosystem = CONFIG_KEYS.get(key);
      if (keyEcosystem === undefined) continue;
      const effectiveEcosystem = keyEcosystem === ecosystem ? ecosystem : keyEcosystem;

      const classification = classifyUrl(url);
      const httpsOnly = url.startsWith("https://");
      out.push({
        classification,
        ecosystem: effectiveEcosystem,
        url,
        httpsOnly,
        location: { kind: "config", file: path, json_pointer: `/${key}` },
        observed: trimmed.slice(0, 200),
        fileLabel: path,
        scoped,
        integrityHashPresent: integrityPresent,
      });
    }
  }
  return out;
}

function parseKeyValue(line: string): { key: string; value: string; scoped: boolean } | null {
  // Support "key = value", "key=value", "@scope:key=value", and "key: value".
  const eq = line.indexOf("=");
  const colon = line.indexOf(":");
  const delim = eq !== -1 && (colon === -1 || eq < colon) ? eq : colon;
  if (delim === -1) return null;
  let keySide = line.slice(0, delim).trim();
  let value = line.slice(delim + 1).trim();
  // Strip optional quotes.
  if (
    (value.startsWith("\"") && value.endsWith("\"")) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    value = value.slice(1, -1);
  }
  let scoped = false;
  // "@scope:registry" → key is "registry", scope is "@scope".
  if (keySide.startsWith("@") && keySide.includes(":")) {
    scoped = true;
    keySide = keySide.slice(keySide.indexOf(":") + 1);
  }
  return { key: keySide, value, scoped };
}

// ─── Source-code scan (env var injection) ─────────────────────────────────

function scanSourceCode(
  file: string,
  source: string,
  integrityPresent: boolean,
): K10Fact[] {
  const out: K10Fact[] = [];
  const sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true);

  const visit = (node: ts.Node): void => {
    // `process.env.NPM_CONFIG_REGISTRY = "..."`
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      ts.isPropertyAccessExpression(node.left)
    ) {
      const envKey = extractProcessEnvKey(node.left);
      if (envKey !== null) {
        const ecosystem = envKeyToEcosystem(envKey);
        if (ecosystem !== null) {
          const value = literalText(node.right);
          if (value !== null && (value.startsWith("http://") || value.startsWith("https://"))) {
            const { line, character } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
            out.push({
              classification: classifyUrl(value),
              ecosystem,
              url: value,
              httpsOnly: value.startsWith("https://"),
              location: { kind: "source", file, line: line + 1, col: character + 1 },
              observed: `${envKey} = "${value}"`,
              fileLabel: file,
              scoped: false,
              integrityHashPresent: integrityPresent,
            });
          }
        }
      }
    }

    // `execSync("npm config set registry https://evil.com")` / child_process.exec(...)
    if (ts.isCallExpression(node)) {
      const first = node.arguments[0];
      if (first !== undefined) {
        const text = literalText(first);
        if (text !== null) {
          const marker = "npm config set registry ";
          const idx = text.indexOf(marker);
          if (idx !== -1) {
            const afterMarker = text.slice(idx + marker.length).trim();
            const url = firstWhitespaceToken(afterMarker);
            if (url !== undefined && (url.startsWith("http://") || url.startsWith("https://"))) {
              const { line, character } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
              out.push({
                classification: classifyUrl(url),
                ecosystem: "npm",
                url,
                httpsOnly: url.startsWith("https://"),
                location: { kind: "source", file, line: line + 1, col: character + 1 },
                observed: text.slice(0, 200),
                fileLabel: file,
                scoped: false,
                integrityHashPresent: integrityPresent,
              });
            }
          }
        }
      }
    }

    ts.forEachChild(node, visit);
  };
  ts.forEachChild(sf, visit);
  return out;
}

function extractProcessEnvKey(node: ts.PropertyAccessExpression): string | null {
  // process.env.FOO  → "FOO"
  // process.env["FOO"] is an ElementAccess — not covered here (extension point).
  const expr = node.expression;
  if (!ts.isPropertyAccessExpression(expr)) return null;
  if (!ts.isIdentifier(expr.expression) || expr.expression.text !== "process") return null;
  if (!ts.isIdentifier(expr.name) || expr.name.text !== "env") return null;
  if (!ts.isIdentifier(node.name)) return null;
  return node.name.text;
}

function envKeyToEcosystem(key: string): Ecosystem | null {
  if (key === "NPM_CONFIG_REGISTRY") return "npm";
  if (key === "NPM_CONFIG_REGISTRY_URL") return "npm";
  if (key === "PIP_INDEX_URL") return "pip";
  if (key === "PIP_EXTRA_INDEX_URL") return "pip";
  if (key === "GOPROXY") return "go";
  if (key === "YARN_NPM_REGISTRY_SERVER") return "yarn";
  return null;
}

function literalText(node: ts.Expression): string | null {
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
  return null;
}

// ─── Classification helpers ────────────────────────────────────────────────

function classifyUrl(url: string): K10Classification {
  const lower = url.toLowerCase();
  for (const host of TRUSTED_HOSTS.keys()) {
    if (lower.includes(host)) return "trusted";
  }
  for (const marker of ENTERPRISE_SUBSTRINGS) {
    if (lower.includes(marker)) return "enterprise-mirror";
  }
  return "untrusted-external";
}

function classifyFilename(path: string): Ecosystem | null {
  const lower = path.toLowerCase();
  for (const [suffix, ecosystem] of CONFIG_FILES) {
    if (lower.endsWith(suffix) || lower.endsWith("/" + suffix)) return ecosystem;
  }
  // Also handle the case where the filename IS the suffix (just ".npmrc" with no dir).
  for (const [suffix, ecosystem] of CONFIG_FILES) {
    const bare = suffix.startsWith(".") ? suffix.slice(1) : suffix;
    if (lower === suffix || lower === "." + bare) return ecosystem;
  }
  return null;
}

function detectIntegrity(context: AnalysisContext): boolean {
  if (!context.source_files) return false;
  for (const [path, text] of context.source_files) {
    const lower = path.toLowerCase();
    if (lower.endsWith("package-lock.json") && text.includes("\"integrity\"")) return true;
    if (lower.endsWith("go.sum")) return true;
    if (lower.endsWith("yarn.lock") && text.includes("integrity")) return true;
    if (lower.endsWith("pip.conf") && text.includes("require-hashes")) return true;
  }
  return false;
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

/** Return the prefix of `s` up to (but not including) the first whitespace character. */
function firstWhitespaceToken(s: string): string {
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === " " || c === "\t" || c === "\n" || c === "\r") return s.slice(0, i);
  }
  return s;
}
