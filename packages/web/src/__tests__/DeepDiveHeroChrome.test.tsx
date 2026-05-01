// @vitest-environment jsdom
/**
 * DeepDiveHeroChrome — helper + slot-rendering tests.
 *
 * The component is an async Server Component that issues an attestation
 * fetch during render — full RSC rendering is brittle without an RSC
 * harness. We test the deterministic surface the same way
 * `SignedEvidencePack.test.ts` does: helpers + a stubbed attestation fetch
 * that lets us assert what the rendered tree looks like in the success
 * and degraded paths.
 *
 * What we guard:
 *   1. scoreBand thresholds match EvidenceSummaryHero (regression guard
 *      against drift between the old 3-column hero and the new strip).
 *   2. scoreToLetter thresholds.
 *   3. coverageBandColor maps each band to the correct CSS var token.
 *   4. The Lethal-trifecta cap caps a 75 score down to 40 and adds the
 *      LETHAL chip when `lethal=true`.
 *   5. Identity slot renders name + version chip.
 *   6. Pip slot reflects had_source_code / had_connection / had_dependencies.
 *   7. The pack disclosure renders as a closed-by-default `<details>`.
 *   8. Attestation fetch failure does not crash the component — chips
 *      fall back to defaults ("HMAC-SHA256", "RFC 8785", "—").
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import React from "react";
import { render } from "@testing-library/react";
import {
  __TEST_scoreBand as scoreBand,
  __TEST_scoreToLetter as scoreToLetter,
  __TEST_bandLabel as bandLabel,
  __TEST_coverageBandLabel as coverageBandLabel,
  __TEST_coverageBandColor as coverageBandColor,
} from "../components/DeepDiveHeroChrome";
import DeepDiveHeroChrome from "../components/DeepDiveHeroChrome";

// ── Helpers ──────────────────────────────────────────────────────────────────

describe("scoreBand", () => {
  it("returns good for >= 80", () => {
    expect(scoreBand(80)).toBe("good");
    expect(scoreBand(99)).toBe("good");
  });
  it("returns moderate for 60..79", () => {
    expect(scoreBand(60)).toBe("moderate");
    expect(scoreBand(79)).toBe("moderate");
  });
  it("returns poor for 40..59", () => {
    expect(scoreBand(40)).toBe("poor");
    expect(scoreBand(59)).toBe("poor");
  });
  it("returns critical below 40", () => {
    expect(scoreBand(0)).toBe("critical");
    expect(scoreBand(39)).toBe("critical");
  });
});

describe("scoreToLetter", () => {
  it("maps thresholds to letters", () => {
    expect(scoreToLetter(95)).toBe("A");
    expect(scoreToLetter(85)).toBe("A−");
    expect(scoreToLetter(75)).toBe("B");
    expect(scoreToLetter(65)).toBe("C");
    expect(scoreToLetter(55)).toBe("D");
    expect(scoreToLetter(45)).toBe("D−");
    expect(scoreToLetter(20)).toBe("F");
  });
});

describe("bandLabel", () => {
  it("returns the human label for each band", () => {
    expect(bandLabel("good")).toBe("Good");
    expect(bandLabel("moderate")).toBe("Moderate");
    expect(bandLabel("poor")).toBe("Poor");
    expect(bandLabel("critical")).toBe("Critical");
  });
});

describe("coverageBandLabel", () => {
  it("returns uppercase labels", () => {
    expect(coverageBandLabel("high")).toBe("HIGH");
    expect(coverageBandLabel("medium")).toBe("MEDIUM");
    expect(coverageBandLabel("low")).toBe("LOW");
    expect(coverageBandLabel("minimal")).toBe("MINIMAL");
  });
});

describe("coverageBandColor", () => {
  it("maps high → --good, medium → --moderate, low → --poor, minimal → --critical", () => {
    expect(coverageBandColor("high")).toBe("var(--good)");
    expect(coverageBandColor("medium")).toBe("var(--moderate)");
    expect(coverageBandColor("low")).toBe("var(--poor)");
    expect(coverageBandColor("minimal")).toBe("var(--critical)");
  });
});

// ── Render path ─────────────────────────────────────────────────────────────
//
// The component awaits a single fetch. We stub fetch globally so the unit
// test runs in jsdom without network. Tests use `await DeepDiveHeroChrome(...)`
// to drive the async render and pipe its output through `render`.

function stubFetch(impl: typeof fetch) {
  const orig = globalThis.fetch;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (globalThis as any).fetch = impl;
  return () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (globalThis as any).fetch = orig;
  };
}

const baseProps = {
  slug: "example-server",
  apiUrl: "https://example.test",
  name: "Example Server",
  server_version: "1.2.3",
  author: "ACME Inc",
  total_score: 72,
  lethal: false,
  coverage_band: "medium" as const,
  had_source_code: true,
  had_connection: true,
  had_dependencies: false,
};

describe("render — happy path", () => {
  let restore: () => void;
  beforeEach(() => {
    restore = stubFetch(async () => {
      const headers = new Headers({
        "x-mcp-sentinel-signature": "abcdef0123456789deadbeef",
        "x-mcp-sentinel-key-id": "key-2026-q2",
        "x-mcp-sentinel-signed-at": new Date().toISOString(),
        "x-mcp-sentinel-algorithm": "HMAC-SHA256",
        "x-mcp-sentinel-canonicalization": "RFC 8785",
      });
      return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
    });
  });
  afterEach(() => restore());

  it("renders identity, score number, letter, and band", async () => {
    const tree = await DeepDiveHeroChrome(baseProps);
    const { container } = render(tree);
    const text = container.textContent ?? "";
    expect(text).toContain("Example Server");
    expect(text).toContain("v1.2.3");
    expect(text).toContain("ACME Inc");
    expect(text).toContain("72");
    expect(container.querySelector(".dd-hero-letter")?.textContent).toBe("B");
    expect(container.querySelector(".dd-hero-band")?.textContent).toBe("Moderate");
  });

  it("renders the confidence chip with the medium label and the three pips", async () => {
    const tree = await DeepDiveHeroChrome(baseProps);
    const { container } = render(tree);
    expect(container.querySelector(".dd-hero-conf-medium")).not.toBeNull();
    expect((container.querySelector(".dd-hero-conf-medium")?.textContent ?? "")).toContain(
      "MEDIUM",
    );
    const pips = container.querySelectorAll(".dd-pip");
    expect(pips).toHaveLength(3);
    // had_dependencies: false → third pip is `dd-pip-off`.
    const labels = Array.from(pips).map((p) => p.querySelector(".dd-pip-label")?.textContent);
    expect(labels).toEqual(["source", "live", "deps"]);
    expect(pips[0].classList.contains("dd-pip-on")).toBe(true);
    expect(pips[1].classList.contains("dd-pip-on")).toBe(true);
    expect(pips[2].classList.contains("dd-pip-off")).toBe(true);
  });

  it("renders the pack disclosure as closed-by-default <details>", async () => {
    const tree = await DeepDiveHeroChrome(baseProps);
    const { container } = render(tree);
    const det = container.querySelector("[data-testid='dd-hero-pack']") as HTMLDetailsElement | null;
    expect(det).not.toBeNull();
    expect(det!.tagName).toBe("DETAILS");
    expect(det!.open).toBe(false);
  });

  it("hides the lethal-trifecta chip when lethal=false", async () => {
    const tree = await DeepDiveHeroChrome(baseProps);
    const { container } = render(tree);
    expect(container.querySelector(".dd-hero-lethal")).toBeNull();
  });
});

describe("render — lethal trifecta cap", () => {
  let restore: () => void;
  beforeEach(() => {
    restore = stubFetch(async () => new Response("not found", { status: 404 }));
  });
  afterEach(() => restore());

  it("caps a 75 score to 40 + renders the LETHAL TRIFECTA chip", async () => {
    const tree = await DeepDiveHeroChrome({
      ...baseProps,
      total_score: 75,
      lethal: true,
    });
    const { container } = render(tree);
    expect(container.querySelector(".dd-hero-lethal")?.textContent).toContain(
      "LETHAL TRIFECTA",
    );
    expect(container.querySelector(".dd-hero-score-num")?.textContent).toBe("40");
    // 40 → "poor" band.
    expect(container.querySelector(".dd-hero-band")?.textContent).toBe("Poor");
  });
});

describe("render — degraded attestation fetch", () => {
  let restore: () => void;
  beforeEach(() => {
    restore = stubFetch(async () => {
      throw new Error("network down");
    });
  });
  afterEach(() => restore());

  it("does not throw and renders the chip defaults when fetch fails", async () => {
    // Component should resolve cleanly; the chips use the fallback strings.
    const tree = await DeepDiveHeroChrome(baseProps);
    const { container } = render(tree);
    const text = container.textContent ?? "";
    expect(text).toContain("HMAC-SHA256");
    expect(text).toContain("RFC 8785");
  });

  it("renders an em-dash for unknown signature/key/signed when fetch fails", async () => {
    const tree = await DeepDiveHeroChrome(baseProps);
    const { container } = render(tree);
    const text = container.textContent ?? "";
    expect(text).toContain("—");
  });
});

describe("render — coverage band absent", () => {
  let restore: () => void;
  beforeEach(() => {
    restore = stubFetch(async () => new Response("nope", { status: 404 }));
  });
  afterEach(() => restore());

  it("hides the confidence chip when coverage_band is null", async () => {
    const tree = await DeepDiveHeroChrome({ ...baseProps, coverage_band: null });
    const { container } = render(tree);
    // No band chip — but pips should still render.
    expect(container.querySelector(".dd-hero-conf")).toBeNull();
    expect(container.querySelectorAll(".dd-pip")).toHaveLength(3);
  });
});

describe("render — null score", () => {
  let restore: () => void;
  beforeEach(() => {
    restore = stubFetch(async () => new Response("nope", { status: 404 }));
  });
  afterEach(() => restore());

  it("renders an em-dash for the score number when total_score is null", async () => {
    const tree = await DeepDiveHeroChrome({ ...baseProps, total_score: null });
    const { container } = render(tree);
    expect(container.querySelector(".dd-hero-score-num")?.textContent).toBe("—");
  });
});
