import { describe, expect, it } from "vitest";

import { jsonRenderer } from "../render/json-renderer.js";
import { makeSyntheticSignedReport } from "./renderer-fixtures.js";

describe("jsonRenderer", () => {
  it("emits valid JSON", () => {
    const signed = makeSyntheticSignedReport("eu_ai_act");
    const text = jsonRenderer.render(signed) as string;
    expect(() => JSON.parse(text)).not.toThrow();
  });

  it("round-trips the signed envelope", () => {
    const signed = makeSyntheticSignedReport("mitre_atlas");
    const text = jsonRenderer.render(signed) as string;
    const parsed = JSON.parse(text);
    expect(parsed).toEqual(signed);
  });

  it("pretty-prints with newlines and 2-space indentation", () => {
    const signed = makeSyntheticSignedReport("owasp_asi");
    const text = jsonRenderer.render(signed) as string;
    expect(text).toContain("\n");
    // First nested line has 2-space indent before a quoted key.
    expect(text).toContain('\n  "');
  });
});
