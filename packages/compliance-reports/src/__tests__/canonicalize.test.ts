import { describe, expect, it } from "vitest";

import { canonicalize, CanonicalizationError } from "../canonicalize.js";

describe("RFC 8785 canonicalization", () => {
  it("produces identical bytes regardless of input key order", () => {
    const a = { b: 2, a: 1, c: 3 };
    const b = { c: 3, a: 1, b: 2 };
    expect(canonicalize(a)).toBe(canonicalize(b));
    expect(canonicalize(a)).toBe('{"a":1,"b":2,"c":3}');
  });

  it("preserves array element order", () => {
    expect(canonicalize([3, 1, 2])).toBe("[3,1,2]");
    expect(canonicalize({ nested: [{ b: 1, a: 2 }, "x"] })).toBe(
      '{"nested":[{"a":2,"b":1},"x"]}',
    );
  });

  it("emits no insignificant whitespace", () => {
    const out = canonicalize({ a: 1, b: [1, 2] });
    expect(out).not.toMatch(/\s/);
  });

  it("serialises primitives per the RFC", () => {
    expect(canonicalize(null)).toBe("null");
    expect(canonicalize(true)).toBe("true");
    expect(canonicalize(false)).toBe("false");
    expect(canonicalize(0)).toBe("0");
    expect(canonicalize(-0)).toBe("0");
    expect(canonicalize(1.5)).toBe("1.5");
    expect(canonicalize(1e21)).toBe("1e+21");
    expect(canonicalize("hello")).toBe('"hello"');
  });

  it("rejects undefined, NaN, and Infinity", () => {
    expect(() => canonicalize(undefined)).toThrow(CanonicalizationError);
    expect(() => canonicalize(NaN)).toThrow(CanonicalizationError);
    expect(() => canonicalize(Infinity)).toThrow(CanonicalizationError);
    expect(() => canonicalize(-Infinity)).toThrow(CanonicalizationError);
  });

  it("escapes only JSON-required control characters and quotes", () => {
    expect(canonicalize("tab\there")).toBe('"tab\\there"');
    expect(canonicalize('say "hi"')).toBe('"say \\"hi\\""');
    expect(canonicalize("back\\slash")).toBe('"back\\\\slash"');
    expect(canonicalize("line\nfeed")).toBe('"line\\nfeed"');
    // Non-ASCII is emitted verbatim (UTF-8 on the wire).
    expect(canonicalize("café")).toBe('"café"');
    // Control chars below 0x20 are hex-escaped.
    expect(canonicalize("")).toBe('"\\u0001"');
  });

  it("sorts keys by UTF-16 code-unit order, not lexicographic collation", () => {
    // U+0061 'a', U+005F '_', U+0041 'A' — underscore < uppercase < lowercase.
    const out = canonicalize({ a: 1, A: 2, _: 3 });
    expect(out).toBe('{"A":2,"_":3,"a":1}');
  });

  it("sorts keys across the full Unicode plane deterministically", () => {
    const obj: Record<string, number> = {};
    // Pick a scattered set of keys spanning ASCII, Latin-1 Supplement, and
    // a surrogate pair so we exercise UTF-16 code-unit (not code-point)
    // ordering. 😀 is U+1F600, which in UTF-16 is D83D DE00 — its first
    // code unit 0xD83D sorts AFTER any BMP character below 0xD800.
    obj["zebra"] = 1;
    obj["café"] = 2;
    obj["ábacus"] = 3;
    obj["_start"] = 4;
    obj["😀grin"] = 5;
    obj["APPLE"] = 6;
    const out = canonicalize(obj);
    // Deterministic snapshot — any change in sort order is a contract break.
    expect(out).toBe(
      '{"APPLE":6,"_start":4,"café":2,"zebra":1,"ábacus":3,"😀grin":5}',
    );
    // Round-trip parse succeeds and preserves values.
    const parsed = JSON.parse(out) as Record<string, number>;
    expect(parsed.zebra).toBe(1);
    expect(parsed["😀grin"]).toBe(5);
  });

  it("drops object keys whose value is undefined (JSON.stringify parity)", () => {
    expect(canonicalize({ a: 1, b: undefined, c: 2 })).toBe('{"a":1,"c":2}');
  });

  it("is deterministic across multiple invocations (round-trip)", () => {
    const value = {
      report: {
        controls: [
          { control_id: "A.8.15", status: "unmet" },
          { control_id: "Art.12", status: "partial" },
        ],
        meta: { version: "1.0", seq: 42 },
      },
    };
    const first = canonicalize(value);
    const second = canonicalize(value);
    const third = canonicalize(JSON.parse(first));
    expect(first).toBe(second);
    expect(first).toBe(third);
  });

  it("canonical form round-trips through JSON.parse → canonicalize", () => {
    const raw = {
      b: [3, 2, 1],
      a: { nested: true, count: 0, name: "x" },
    };
    const first = canonicalize(raw);
    const second = canonicalize(JSON.parse(first));
    expect(first).toBe(second);
  });
});
