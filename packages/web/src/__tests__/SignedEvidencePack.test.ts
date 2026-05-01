/**
 * SignedEvidencePack — helper + framework-id parity tests.
 *
 * Component itself is an async Server Component (RSC) that issues a fetch
 * during render — unit-testing the rendered tree is brittle without a full
 * RSC test harness. We test the deterministic surface area instead:
 *   1. shortHash() abbreviation behaviour
 *   2. fmtSignedAt() relative/absolute formatting
 *   3. The 7 framework ids match the API contract documented in
 *      packages/api/CLAUDE.md (the backend enforces this list via
 *      FRAMEWORK_IDS from @mcp-sentinel/compliance-reports).
 *
 * If the API ever ships a new framework, both this constant and the API
 * docs change in lockstep. This test forces the UI list to keep pace.
 */

import { describe, it, expect } from "vitest";
import {
  shortHash,
  fmtSignedAt,
  __TEST_FRAMEWORKS,
} from "../components/SignedEvidencePack";

describe("shortHash", () => {
  it("returns em-dash for null/empty", () => {
    expect(shortHash(null)).toBe("—");
    expect(shortHash(null, 5, 5)).toBe("—");
  });

  it("returns the original string when shorter than head + tail + 1", () => {
    expect(shortHash("abc")).toBe("abc");
    expect(shortHash("abcdefghijk", 6, 4)).toBe("abcdefghijk");
  });

  it("abbreviates with an ellipsis between head and tail", () => {
    const sig = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const out = shortHash(sig, 12, 4);
    expect(out.startsWith("0123456789ab")).toBe(true);
    expect(out.endsWith("cdef")).toBe(true);
    expect(out).toContain("…");
  });
});

describe("fmtSignedAt", () => {
  it("returns em-dash for null", () => {
    expect(fmtSignedAt(null)).toBe("—");
  });

  it("returns 'just now' for very recent timestamps", () => {
    expect(fmtSignedAt(new Date().toISOString())).toBe("just now");
  });

  it("returns minutes-ago for sub-hour timestamps", () => {
    const d = new Date(Date.now() - 5 * 60_000).toISOString();
    expect(fmtSignedAt(d)).toBe("5m ago");
  });

  it("returns hours-ago for sub-day timestamps", () => {
    const d = new Date(Date.now() - 3 * 3_600_000).toISOString();
    expect(fmtSignedAt(d)).toBe("3h ago");
  });

  it("falls back to a date for older timestamps", () => {
    const d = new Date(Date.now() - 10 * 86_400_000).toISOString();
    const out = fmtSignedAt(d);
    expect(out).not.toMatch(/ago$/);
    expect(out).not.toBe("—");
  });

  it("returns a date (not 'in the future') for clock-skewed future timestamps", () => {
    // Server clock can be slightly ahead; the helper must not throw or render
    // a confusing "—" — it should fall through to date formatting.
    const future = new Date(Date.now() + 60_000).toISOString();
    const out = fmtSignedAt(future);
    expect(out).not.toBe("—");
    expect(out).not.toMatch(/ago$/);
  });
});

describe("__TEST_FRAMEWORKS — API contract parity", () => {
  it("ships exactly the 7 framework ids the API exposes", () => {
    // Source of truth: packages/api/CLAUDE.md and FRAMEWORK_IDS in
    // @mcp-sentinel/compliance-reports. If a framework is added or removed
    // upstream, this list MUST change in the same PR.
    const expected = new Set([
      "eu_ai_act",
      "iso_27001",
      "owasp_mcp",
      "owasp_asi",
      "cosai_mcp",
      "maestro",
      "mitre_atlas",
    ]);
    const actual = new Set(__TEST_FRAMEWORKS.map((f) => f.id));
    expect(actual).toEqual(expected);
  });

  it("every framework has a non-empty label and subtitle", () => {
    for (const fw of __TEST_FRAMEWORKS) {
      expect(fw.label.length).toBeGreaterThan(0);
      expect(fw.sub.length).toBeGreaterThan(0);
    }
  });
});
