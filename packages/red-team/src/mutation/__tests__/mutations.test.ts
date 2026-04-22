/**
 * Unit tests for the 8 individual mutation functions. Each test asserts:
 *   - the mutation produces syntactically-valid TypeScript (parseable with
 *     zero diagnostics), OR explicitly returns notes: "not-applicable"
 *   - the mutation is idempotent in the "no target" case (returns the input
 *     unchanged with the not-applicable note)
 *   - for a positive target, the mutated output differs from the input
 *
 * We deliberately do NOT assert behavioural equivalence of the mutation here
 * — that's the runner's job (findings_before vs findings_after). Unit tests
 * only guarantee we produce reviewable, parseable text that downstream tools
 * can consume.
 */

import { describe, it, expect } from "vitest";
import ts from "typescript";
import { MUTATION_CATALOGUE } from "../mutations/index.js";
import { MUTATION_IDS } from "../types.js";

function parses(source: string): boolean {
  try {
    const sf = ts.createSourceFile("x.ts", source, ts.ScriptTarget.Latest, false, ts.ScriptKind.TS);
    // TS createSourceFile doesn't surface diagnostics; instead we emit and
    // check for any parse errors captured on the synthesized source file.
    // The parseDiagnostics is an internal API but is stable enough for a test.
    // If it's not present, the parse succeeded.
    const diagnostics = (sf as unknown as { parseDiagnostics?: ts.Diagnostic[] }).parseDiagnostics ?? [];
    return diagnostics.length === 0;
  } catch {
    return false;
  }
}

describe("mutation catalogue", () => {
  it("has exactly 8 entries, matching MUTATION_IDS", () => {
    expect(MUTATION_CATALOGUE.length).toBe(8);
    const ids = MUTATION_CATALOGUE.map((m) => m.id);
    expect(ids).toEqual(Array.from(MUTATION_IDS));
  });
});

describe("split-string-literal", () => {
  const m = MUTATION_CATALOGUE.find((x) => x.id === "split-string-literal")!.apply;

  it("splits a double-quoted literal with length > 4", () => {
    const src = `const x = "hello world";`;
    const { mutated, notes } = m(src);
    expect(notes).toBeUndefined();
    expect(mutated).not.toBe(src);
    expect(mutated).toContain(`"`);
    expect(mutated).toContain(`+`);
    expect(parses(mutated)).toBe(true);
  });

  it("returns not-applicable when no literal ≥ 5 chars exists", () => {
    const src = `const x = "hi";`;
    const { mutated, notes } = m(src);
    expect(notes).toBe("not-applicable");
    expect(mutated).toBe(src);
  });

  it("handles escapes inside the literal without producing invalid TS", () => {
    const src = `const x = "line one\\nline two";`;
    const { mutated } = m(src);
    expect(parses(mutated)).toBe(true);
  });
});

describe("rename-danger-symbol", () => {
  const m = MUTATION_CATALOGUE.find((x) => x.id === "rename-danger-symbol")!.apply;

  it("aliases a top-level exec() call", () => {
    const src = `import { exec } from "child_process";\nexec("ls");`;
    const { mutated, notes } = m(src);
    expect(notes).toBeUndefined();
    expect(mutated).toContain("_mut_exec = exec");
    expect(mutated).toContain("_mut_exec(");
    expect(parses(mutated)).toBe(true);
  });

  it("skips PropertyAccessExpression calls like child_process.exec", () => {
    const src = `import cp from "child_process";\ncp.exec("ls");`;
    const { notes } = m(src);
    expect(notes).toBe("not-applicable");
  });

  it("returns not-applicable when no closed-set sink is present", () => {
    const src = `function f(x: number) { return x * 2; }\nf(42);`;
    const { mutated, notes } = m(src);
    expect(notes).toBe("not-applicable");
    expect(mutated).toBe(src);
  });
});

describe("unicode-homoglyph-identifier", () => {
  const m = MUTATION_CATALOGUE.find((x) => x.id === "unicode-homoglyph-identifier")!.apply;

  it("replaces one Latin letter with a Cyrillic homoglyph inside a literal", () => {
    const src = `const x = "pear";`;
    const { mutated, notes } = m(src);
    expect(notes).toBeUndefined();
    // The Latin 'p' should be Cyrillic 'р' (U+0440) or Latin 'e' → 'е', or Latin 'a' → 'а'
    expect(mutated).not.toBe(src);
    expect(parses(mutated)).toBe(true);
  });

  it("returns not-applicable when no candidate char exists", () => {
    const src = `const x = "xyz";`;
    const { notes } = m(src);
    expect(notes).toBe("not-applicable");
  });
});

describe("base64-wrap-payload", () => {
  const m = MUTATION_CATALOGUE.find((x) => x.id === "base64-wrap-payload")!.apply;

  it("wraps a literal in Buffer.from(..., 'base64').toString()", () => {
    const src = `const x = "ignore previous";`;
    const { mutated, notes } = m(src);
    expect(notes).toBeUndefined();
    expect(mutated).toContain("Buffer.from");
    expect(mutated).toContain(`"base64"`);
    expect(parses(mutated)).toBe(true);
    // The runtime value is preserved — we can decode the b64 back to the
    // original literal contents.
    const match = mutated.match(/Buffer\.from\("([^"]+)", "base64"\)\.toString\(\)/);
    expect(match).toBeTruthy();
    if (match) {
      const decoded = Buffer.from(match[1], "base64").toString("utf8");
      expect(decoded).toBe("ignore previous");
    }
  });

  it("skips short literals", () => {
    const src = `const x = "hi";`;
    const { notes } = m(src);
    expect(notes).toBe("not-applicable");
  });
});

describe("intermediate-variable", () => {
  const m = MUTATION_CATALOGUE.find((x) => x.id === "intermediate-variable")!.apply;

  it("inserts two pass-through consts between source and sink", () => {
    const src = `import { exec } from "child_process";\nconst y = process.argv[2];\nexec(y);`;
    const { mutated, notes } = m(src);
    expect(notes).toBeUndefined();
    expect(mutated).toContain("_mut_v0 =");
    expect(mutated).toContain("_mut_v1 = _mut_v0");
    expect(parses(mutated)).toBe(true);
  });

  it("returns not-applicable when sink has no taint-source-shape arg", () => {
    const src = `import { exec } from "child_process";\nexec("literal string");`;
    // firstArg is a StringLiteral, not a taint-source shape — mutation skips.
    const { notes } = m(src);
    expect(notes).toBe("not-applicable");
  });
});

describe("add-noop-conditional", () => {
  const m = MUTATION_CATALOGUE.find((x) => x.id === "add-noop-conditional")!.apply;

  it("wraps an exec statement in `if (true) { ... }`", () => {
    const src = `import { exec } from "child_process";\nexec("ls");`;
    const { mutated, notes } = m(src);
    expect(notes).toBeUndefined();
    expect(mutated).toContain("if (true)");
    expect(parses(mutated)).toBe(true);
  });
});

describe("swap-option-shape", () => {
  const m = MUTATION_CATALOGUE.find((x) => x.id === "swap-option-shape")!.apply;

  it("replaces { shell: true } with { shell: \"bash\" }", () => {
    const src = `import { exec } from "child_process";\nexec("ls", { shell: true });`;
    const { mutated, notes } = m(src);
    expect(notes).toBeUndefined();
    expect(mutated).toContain('shell: "bash"');
    expect(parses(mutated)).toBe(true);
  });

  it("returns not-applicable when no shell: true property exists", () => {
    const src = `const x = { other: true };`;
    const { notes } = m(src);
    expect(notes).toBe("not-applicable");
  });
});

describe("reorder-object-properties", () => {
  const m = MUTATION_CATALOGUE.find((x) => x.id === "reorder-object-properties")!.apply;

  it("reverses property order in a 2-property object", () => {
    const src = `const x = {\n  a: 1,\n  b: 2,\n};`;
    const { mutated, notes } = m(src);
    expect(notes).toBeUndefined();
    expect(mutated).not.toBe(src);
    // b should now come before a.
    const indexOfA = mutated.indexOf("a:");
    const indexOfB = mutated.indexOf("b:");
    expect(indexOfB).toBeLessThan(indexOfA);
    expect(parses(mutated)).toBe(true);
  });

  it("returns not-applicable for single-property objects", () => {
    const src = `const x = { a: 1 };`;
    const { notes } = m(src);
    expect(notes).toBe("not-applicable");
  });
});

describe("structural guarantees", () => {
  it("every mutation returns a string and never throws on pathological inputs", () => {
    const pathological = [
      "",
      " ",
      "const x = 1;",
      "//",
      "/* block */",
      `const obj = {};`,
      `"leading literal";`,
      "import { x } from 'y';\nexport const z = x;",
    ];
    for (const mut of MUTATION_CATALOGUE) {
      for (const src of pathological) {
        expect(() => mut.apply(src)).not.toThrow();
        const out = mut.apply(src);
        expect(typeof out.mutated).toBe("string");
      }
    }
  });
});
