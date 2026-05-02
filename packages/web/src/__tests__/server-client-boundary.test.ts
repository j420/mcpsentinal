/**
 * Regression: server components MUST NOT call functions exported from a
 * "use client" module.
 *
 * Production hit HTTP 500 on /servers/[slug] (digest 1244316665) because
 * page.tsx imported `resolveLensDensity` from
 * `@/components/LensDensityControls` — a "use client" file — and called
 * it during SSR. Next 15 raises:
 *
 *   Error: Attempted to call resolveLensDensity() from the server but
 *   resolveLensDensity is on the client. It's not possible to invoke a
 *   client function from the server, it can only be rendered as a
 *   Component or passed to props of a Client Component.
 *
 * The error is framework-level — it bypasses every <SectionBoundary/>
 * (which only catches React render-phase exceptions) and surfaces as
 * HTTP 500 from the route-level error.tsx.
 *
 * Fix discipline: any helper called from a server component MUST live in
 * a non-`"use client"` module (lib/, anything that doesn't start with
 * `"use client";`). Default-imports of components (`import Foo from
 * "@/components/Foo"`) are fine — those are JSX-rendered, not invoked.
 *
 * What this guard checks (source-level, same pattern as
 * page-safe-coercion.test.ts and RuleEvidenceCard.suspense-guard.test.ts):
 *   - For each `import { X, Y } from "@/components/<file>"` in page.tsx,
 *     read the target file and verify it does NOT start with `"use client"`,
 *     OR the named imports must be types only (re-export aliases).
 *   - The default-import alongside named imports is allowed (it's a JSX
 *     component, not a callable from the server).
 *
 * This catches not just the resolveLensDensity slip, but ANY future
 * named import of a function from a "use client" module by the server
 * page — exactly the framework boundary that has bitten this page now
 * twice (once via Suspense, now via client-function call).
 */

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const PAGE_PATH = resolve(
  __dirname,
  "..",
  "app",
  "servers",
  "[slug]",
  "page.tsx",
);
const COMPONENTS_DIR = resolve(__dirname, "..", "components");
const LIB_DIR = resolve(__dirname, "..", "lib");

const PAGE_SOURCE = readFileSync(PAGE_PATH, "utf-8");

interface ParsedImport {
  source: string;
  defaultName: string | null;
  namedNames: string[];
  /** True if every named import was prefixed with `type` (TS-only). */
  allTypeOnly: boolean;
  raw: string;
}

/**
 * Tiny tolerant parser for ES `import` statements. Handles:
 *   - `import Foo from "x";`
 *   - `import { a, b } from "x";`
 *   - `import Foo, { a, b } from "x";`
 *   - `import { type a, type b } from "x";`  (TS type-only named imports)
 *   - multi-line forms with line breaks inside `{ ... }`
 *
 * Skips `import type { ... }` statements entirely (TS-only, never reaches
 * runtime, never causes a Next 15 client-function-call error).
 */
function parseImports(source: string): ParsedImport[] {
  const out: ParsedImport[] = [];
  // Multi-line tolerant: capture until the next `from "..."` then `;`.
  const re = /import\s+(?!type\b)([^;]*?)\s+from\s+["']([^"']+)["']\s*;/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(source)) !== null) {
    const clause = m[1].trim();
    const src = m[2];

    let defaultName: string | null = null;
    let bracePart: string | null = null;

    if (clause.startsWith("{")) {
      bracePart = clause;
    } else {
      // `Foo` or `Foo, { a, b }`
      const commaIdx = clause.indexOf(",");
      if (commaIdx === -1) {
        defaultName = clause.trim() || null;
      } else {
        defaultName = clause.slice(0, commaIdx).trim();
        bracePart = clause.slice(commaIdx + 1).trim();
      }
    }

    let namedNames: string[] = [];
    let allTypeOnly = true;
    if (bracePart) {
      const inner = bracePart.replace(/^\{/, "").replace(/\}$/, "");
      const items = inner
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      for (const item of items) {
        if (/^type\s+/.test(item)) {
          // type-only — does not reach runtime
          continue;
        }
        allTypeOnly = false;
        // strip `as Foo` aliases for our purposes
        const name = item.split(/\s+as\s+/)[0].trim();
        // strip leading `* as Foo` too
        if (name && !name.startsWith("*")) namedNames.push(name);
      }
    }

    out.push({
      source: src,
      defaultName,
      namedNames,
      allTypeOnly: namedNames.length === 0 || allTypeOnly,
      raw: m[0],
    });
  }
  return out;
}

function resolveImportPath(
  importSource: string,
): { kind: "components" | "lib" | "other"; path: string } | null {
  if (importSource.startsWith("@/components/")) {
    const tail = importSource.replace("@/components/", "");
    return { kind: "components", path: resolve(COMPONENTS_DIR, `${tail}.tsx`) };
  }
  if (importSource.startsWith("@/lib/")) {
    const tail = importSource.replace("@/lib/", "");
    return { kind: "lib", path: resolve(LIB_DIR, `${tail}.ts`) };
  }
  return null;
}

function isClientModule(path: string): boolean {
  try {
    const src = readFileSync(path, "utf-8");
    // First ~120 chars catches the "use client" pragma even when there's
    // a leading comment. Real client modules put the directive on line 1.
    const head = src.slice(0, 200);
    return /^\s*"use client"\s*;?/m.test(head);
  } catch {
    return false;
  }
}

describe("/servers/[slug]/page.tsx — server/client boundary discipline", () => {
  it("the page.tsx parser sees a non-trivial import list", () => {
    const imports = parseImports(PAGE_SOURCE);
    expect(imports.length).toBeGreaterThan(5);
  });

  it("does NOT call any function imported from a 'use client' module", () => {
    const imports = parseImports(PAGE_SOURCE);

    const violations: Array<{ source: string; names: string[] }> = [];
    for (const imp of imports) {
      const resolved = resolveImportPath(imp.source);
      if (!resolved || resolved.kind !== "components") continue;
      // Default import is a component rendered as JSX (`<Foo .../>`) —
      // safe regardless of "use client".
      // Named imports of TYPES are also safe (they vanish at runtime).
      if (imp.namedNames.length === 0) continue;
      if (imp.allTypeOnly) continue;
      if (!isClientModule(resolved.path)) continue;
      violations.push({ source: imp.source, names: imp.namedNames });
    }

    if (violations.length > 0) {
      const detail = violations
        .map(
          (v) =>
            `  - "${v.source}" exports a "use client" module; named imports {${v.names.join(", ")}} are at risk of being called server-side.`,
        )
        .join("\n");
      throw new Error(
        `page.tsx imports runtime values from "use client" modules — Next 15 will crash SSR with "Attempted to call X from the server but X is on the client" (digest 1244316665):\n${detail}\n\nFix: move the helper(s) to a non-"use client" module (e.g. packages/web/src/lib/) and update both call sites.`,
      );
    }
  });

  it("specifically: resolveLensDensity is imported from @/lib/lens-density (not the controls module)", () => {
    // Direct, named guard for the exact mistake that crashed production.
    // Use the parsed import list rather than regexes — substring searches
    // are too greedy on a long file (the identifier appears as a call
    // site later in the file, which a [\s\S]* span will happily match).
    const imports = parseImports(PAGE_SOURCE);

    // Must be imported from the lib module.
    const fromLib = imports.find(
      (i) =>
        i.source === "@/lib/lens-density" &&
        i.namedNames.includes("resolveLensDensity"),
    );
    expect(fromLib, "resolveLensDensity should be imported from @/lib/lens-density").toBeTruthy();

    // Must NOT appear in any named-import list from the controls module.
    const fromControls = imports.find(
      (i) =>
        i.source === "@/components/LensDensityControls" &&
        i.namedNames.includes("resolveLensDensity"),
    );
    expect(
      fromControls,
      "resolveLensDensity must not be imported from the 'use client' controls module",
    ).toBeUndefined();
  });

  it("specifically: @/lib/lens-density is not a 'use client' module", () => {
    const path = resolve(LIB_DIR, "lens-density.ts");
    expect(isClientModule(path)).toBe(false);
  });
});
