/**
 * K9 — Dangerous Post-Install Hooks: fact gatherer.
 *
 * Unlike the other five taint-based rules, K9's "source code" input is a
 * MANIFEST file (package.json / setup.py / pyproject.toml). The detection
 * pipeline is therefore structural first, taint second:
 *
 *   1. Structural — attempt to JSON.parse the source. If successful and
 *      the document has a `scripts` object, inspect each install-lifecycle
 *      hook (postinstall / preinstall / install / postpack / prepack) by
 *      substring-matching against DANGEROUS_TOKEN_FAMILIES. Produces one
 *      K9Fact per hit, tagged with the hook key + matched family.
 *
 *   2. Python taint — regardless of JSON parsing success, also run the
 *      lightweight taint analyser on the source. A Python setup.py with
 *      a subprocess-calling cmdclass will show up as a command_execution
 *      sink; we convert those to K9Facts tagged family="subprocess-call".
 *
 * No regex literals. All patterns live under `data/` (guard-skipped).
 * Every Location emitted carries `kind: "config"` (pointing at the JSON
 * pointer for the offending hook) or `kind: "source"` (for taint-found
 * Python flows).
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  analyzeTaint,
} from "../../analyzers/taint.js";
import {
  DANGEROUS_TOKEN_FAMILIES,
  INSTALL_HOOK_KEYS,
  KNOWN_BUILD_TOKENS,
  type DangerousTokenFamily,
} from "./data/dangerous-tokens.js";

// ─── Fact type ────────────────────────────────────────────────────────────

export interface K9Fact {
  /** Which hook the finding is rooted in ("postinstall" / "setup.py-cmdclass"). */
  hook: string;
  /** Dangerous-family classification. */
  family: DangerousTokenFamily["family"];
  /** Severity drawn from the family. */
  severity: DangerousTokenFamily["severity"];
  /** Matched token (capped). */
  matchedToken: string;
  /** Hook-body snippet (capped). */
  hookSnippet: string;
  /** Location for the source link ("config" for JSON, "source" for taint). */
  location: Location;
  /** How confident the token match is (primary / lightweight). */
  origin: "structural" | "taint";
  /** Human description pulled from the token family. */
  description: string;
}

export interface K9GatherResult {
  mode: "absent" | "test-file" | "facts";
  facts: K9Fact[];
}

// ─── Test-file marker skip (same list as the shared kit) ──────────────────

function isTestFileShape(source: string): boolean {
  // Small list — under 5 — kept in code because this is the K9-specific
  // layer that needs to NOT skip JSON package.json inputs that happen to
  // include the word "test" (every package.json has a "test" script).
  return (
    source.includes("__tests__") ||
    source.includes(".test.") ||
    source.includes(".spec.") ||
    source.includes('from "vitest"') ||
    source.includes("describe(")
  );
}

// ─── Structural JSON gatherer ─────────────────────────────────────────────

function gatherFromJson(source: string): K9Fact[] {
  // Try to parse — package.json is the primary input shape.
  let parsed: unknown;
  try {
    parsed = JSON.parse(source);
  } catch {
    return [];
  }

  if (typeof parsed !== "object" || parsed === null) return [];
  const scripts = (parsed as { scripts?: Record<string, unknown> }).scripts;
  if (!scripts || typeof scripts !== "object") return [];

  const out: K9Fact[] = [];
  for (const hook of INSTALL_HOOK_KEYS) {
    const value = (scripts as Record<string, unknown>)[hook];
    if (typeof value !== "string" || value.length === 0) continue;

    // Only-build-tokens shortcut — `postinstall: "npx tsc"` etc.
    if (isOnlyBuildTokens(value)) continue;

    for (const family of DANGEROUS_TOKEN_FAMILIES) {
      const match = findFirstToken(value, family.tokens);
      if (!match) continue;
      const location: Location = {
        kind: "config",
        file: "package.json",
        json_pointer: `/scripts/${hook}`,
      };
      out.push({
        hook,
        family: family.family,
        severity: family.severity,
        matchedToken: match,
        hookSnippet: value.slice(0, 240),
        location,
        origin: "structural",
        description: family.description,
      });
      break; // one finding per (hook, family) — stop at first family match
    }
  }
  return out;
}

function isOnlyBuildTokens(body: string): boolean {
  // If the body contains a known build token and none of the dangerous
  // family tokens, treat as safe.
  let hasBuild = false;
  for (const token of KNOWN_BUILD_TOKENS) {
    if (body.includes(token)) {
      hasBuild = true;
      break;
    }
  }
  if (!hasBuild) return false;
  // But if any dangerous family token also appears, it's NOT safe.
  for (const family of DANGEROUS_TOKEN_FAMILIES) {
    if (findFirstToken(body, family.tokens)) return false;
  }
  return true;
}

function findFirstToken(body: string, tokens: readonly string[]): string | null {
  for (const t of tokens) {
    if (body.includes(t)) return t;
  }
  return null;
}

// ─── Python setup.py gatherer (lightweight taint) ──────────────────────────

function gatherFromPythonTaint(source: string): K9Fact[] {
  // Only run this when we see structural signals that this IS a setup.py
  // or a Python cmdclass file — the lightweight analyser fires on any
  // subprocess call otherwise, which would false-positive on legit code.
  const hasInstallClass =
    source.includes("class PostInstall") ||
    source.includes("class Install") ||
    source.includes("cmdclass");
  if (!hasInstallClass) return [];

  const out: K9Fact[] = [];
  try {
    const flows = analyzeTaint(source);
    for (const flow of flows) {
      if (flow.sink.category !== "command_execution" && flow.sink.category !== "url_request") {
        continue;
      }
      const family: DangerousTokenFamily["family"] = flow.sink.category === "url_request" ? "fetch-and-exec" : "subprocess-call";
      out.push({
        hook: "setup.py-cmdclass",
        family,
        severity: "critical",
        matchedToken: flow.sink.expression.slice(0, 120),
        hookSnippet: flow.sink.expression.slice(0, 240),
        location: {
          kind: "source",
          file: "setup.py",
          line: flow.sink.line,
          col: 1,
        } satisfies Location,
        origin: "taint",
        description:
          family === "fetch-and-exec"
            ? "setup.py cmdclass performs a network request during install — supply-chain RCE vector"
            : "setup.py cmdclass spawns a subprocess during install — supply-chain RCE vector",
      });
    }
  } catch {
    // defensive only
  }
  return out;
}

// ─── Public entry point ───────────────────────────────────────────────────

export function gatherK9(context: AnalysisContext): K9GatherResult {
  const source = context.source_code;
  if (!source || source.length === 0) {
    return { mode: "absent", facts: [] };
  }
  if (isTestFileShape(source)) {
    return { mode: "test-file", facts: [] };
  }

  const facts = [...gatherFromJson(source), ...gatherFromPythonTaint(source)];
  return { mode: facts.length > 0 ? "facts" : "absent", facts };
}
