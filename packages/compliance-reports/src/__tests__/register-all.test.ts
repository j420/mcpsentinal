import { beforeAll, describe, expect, it } from "vitest";

import { getAllRenderers, getRenderer, __clearRendererRegistry } from "../render/types.js";
import type { RendererFormat } from "../render/types.js";
import { FRAMEWORK_IDS } from "../types.js";
import type { FrameworkId } from "../types.js";

// Ensure we start from a known-empty registry, then re-register by re-evaluating
// the module. Because `register-all.ts` runs at import time via side effects,
// we first clear, then import the module dynamically.
beforeAll(async () => {
  __clearRendererRegistry();
  await import("../render/register-all.js");
});

const FORMATS: RendererFormat[] = ["html", "json", "pdf"];

describe("register-all", () => {
  it("registers 21 (format × framework) entries", () => {
    expect(getAllRenderers()).toHaveLength(FORMATS.length * FRAMEWORK_IDS.length);
  });

  it("has a renderer for every (format, framework) combination", () => {
    for (const format of FORMATS) {
      for (const framework of FRAMEWORK_IDS as readonly FrameworkId[]) {
        const r = getRenderer(format, framework);
        expect(r, `missing ${format}:${framework}`).toBeDefined();
        expect(r!.format).toBe(format);
      }
    }
  });

  it("uses one shared implementation per format across all frameworks", () => {
    // Architectural invariant: framework-specific content already lives in
    // the signed report, so we deliberately register ONE impl per format
    // seven times. Same instance, not a clone.
    for (const format of FORMATS) {
      const rendered = FRAMEWORK_IDS.map((f) => getRenderer(format, f as FrameworkId));
      const first = rendered[0];
      expect(first).toBeDefined();
      for (const r of rendered) {
        expect(r).toBe(first);
      }
    }
  });
});
