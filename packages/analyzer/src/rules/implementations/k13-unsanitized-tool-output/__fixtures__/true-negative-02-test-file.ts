/**
 * K13 TN-02 — structural test file. Fetch → return inside a vitest
 * `it(...)` callback. The file is skipped wholesale.
 */

import { describe, it, expect } from "vitest";

describe("scraper", () => {
  it("returns remote content", async () => {
    const page = await fetch("https://example.com");
    const html = await page.text();
    expect(html).toBeDefined();
    return html;
  });
});
