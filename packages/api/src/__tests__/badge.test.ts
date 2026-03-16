/**
 * Badge SVG Security Tests
 *
 * The badge is embedded in external READMEs and web pages. Any text that flows
 * into the SVG must be XML-escaped to prevent:
 *
 *   1. SVG attribute injection (aria-label, clip-path ids)
 *   2. XML tag injection (closing </title> and injecting new elements)
 *   3. Script execution when badge is inlined in HTML
 *
 * Every test verifies a specific injection payload is defused in the output.
 */

import { describe, it, expect } from "vitest";
import { createBadgeSvg } from "../badge.js";

// Helper: parse out the aria-label attribute value from raw SVG
function extractAriaLabel(svg: string): string {
  const m = svg.match(/aria-label="([^"]*)"/);
  return m?.[1] ?? "";
}

// Helper: parse out the <title> tag contents from raw SVG
function extractTitle(svg: string): string {
  const m = svg.match(/<title>([\s\S]*?)<\/title>/);
  return m?.[1] ?? "";
}

// Helper: extract the first text node value after the label rectangle
function extractTextNodes(svg: string): string[] {
  const matches = [...svg.matchAll(/<text[^>]*>([^<]*)<\/text>/g)];
  return matches.map((m) => m[1] ?? "");
}

// ─── Basic functionality ───────────────────────────────────────────────────────

describe("createBadgeSvg — basic output", () => {
  it("produces valid SVG XML", () => {
    const svg = createBadgeSvg("mcp sentinel", "85/100", "#4c1");
    expect(svg).toMatch(/^<svg /);
    expect(svg).toContain("</svg>");
    expect(svg).toContain('xmlns="http://www.w3.org/2000/svg"');
  });

  it("includes the label and value text", () => {
    const svg = createBadgeSvg("mcp sentinel", "72/100", "#dfb317");
    const texts = extractTextNodes(svg);
    // Text nodes appear twice each (shadow + foreground) in the badge style
    expect(texts.some((t) => t.includes("mcp sentinel"))).toBe(true);
    expect(texts.some((t) => t.includes("72/100"))).toBe(true);
  });

  it("sets the aria-label correctly for accessibility", () => {
    const svg = createBadgeSvg("mcp sentinel", "90/100", "#4c1");
    expect(extractAriaLabel(svg)).toBe("mcp sentinel: 90/100");
  });

  it("sets the <title> correctly for tooltip display", () => {
    const svg = createBadgeSvg("mcp sentinel", "40/100", "#fe7d37");
    expect(extractTitle(svg)).toBe("mcp sentinel: 40/100");
  });
});

// ─── XML / SVG injection — label parameter ────────────────────────────────────

describe("createBadgeSvg — injection via label", () => {
  it('escapes < and > in aria-label (tag injection attempt)', () => {
    const svg = createBadgeSvg('<script>alert(1)</script>', "ok", "#4c1");
    const ariaLabel = extractAriaLabel(svg);
    expect(ariaLabel).not.toContain("<script>");
    expect(ariaLabel).toContain("&lt;script&gt;");
  });

  it('escapes < and > in <title> (tag injection attempt)', () => {
    const svg = createBadgeSvg('</title><script>alert(1)</script><title>', "ok", "#4c1");
    // The title element must remain a single closed element with no injection
    const title = extractTitle(svg);
    expect(title).not.toContain("<script>");
    expect(title).toContain("&lt;/title&gt;");
  });

  it('escapes < and > in text nodes', () => {
    const svg = createBadgeSvg('<evil>', "ok", "#4c1");
    const texts = extractTextNodes(svg);
    expect(texts.every((t) => !t.includes("<evil>"))).toBe(true);
    expect(texts.some((t) => t.includes("&lt;evil&gt;"))).toBe(true);
  });

  it('escapes double quotes in aria-label (attribute injection)', () => {
    // Attempt: close aria-label and add onclick="alert(1)"
    const svg = createBadgeSvg('"onmouseover="alert(1)"', "ok", "#4c1");
    const ariaLabel = extractAriaLabel(svg);
    // The aria-label value must not contain a raw double-quote that could break out
    expect(ariaLabel).not.toContain('"onmouseover=');
    expect(ariaLabel).toContain("&quot;");
  });

  it('escapes single quotes in label (alternate attribute injection)', () => {
    const svg = createBadgeSvg("it's dangerous", "ok", "#4c1");
    // Single quotes must be escaped — some SVG attributes use single-quote delimiters
    expect(svg).toContain("&#39;");
    expect(svg).not.toContain(`it's`); // raw apostrophe must be gone
  });

  it('escapes & in label (XML entity injection)', () => {
    // Bare & is invalid XML and could be used to inject entities
    const svg = createBadgeSvg("foo & bar", "ok", "#4c1");
    const ariaLabel = extractAriaLabel(svg);
    expect(ariaLabel).not.toContain(" & ");
    expect(ariaLabel).toContain("&amp;");
  });

  it('prevents double-escaping when & appears in payload', () => {
    // &amp; should not become &amp;amp;
    const svg = createBadgeSvg("&amp;", "ok", "#4c1");
    const title = extractTitle(svg);
    // The literal string "&amp;" entered by user must appear as "&amp;amp;" after escaping
    expect(title).toContain("&amp;amp;");
    expect(title).not.toContain("&&");
  });
});

// ─── XML / SVG injection — value parameter ────────────────────────────────────

describe("createBadgeSvg — injection via value", () => {
  it('escapes tag injection in value', () => {
    const svg = createBadgeSvg("mcp sentinel", '<img onerror="alert(1)">', "#4c1");
    const title = extractTitle(svg);
    expect(title).not.toContain("<img");
    expect(title).toContain("&lt;img");
  });

  it('escapes attribute injection in value', () => {
    const svg = createBadgeSvg("mcp sentinel", '" onload="alert(1)"', "#4c1");
    const ariaLabel = extractAriaLabel(svg);
    expect(ariaLabel).not.toContain('" onload=');
    expect(ariaLabel).toContain("&quot;");
  });

  it('escapes & in value', () => {
    const svg = createBadgeSvg("mcp sentinel", "A&B", "#4c1");
    expect(extractTitle(svg)).toContain("A&amp;B");
  });

  it('escapes SVG CDATA closing sequence in value', () => {
    // Attempt to break out of a CDATA section (not used here, but defensive)
    const svg = createBadgeSvg("mcp sentinel", "]]><script>alert(1)</script>", "#4c1");
    expect(svg).not.toContain("]]><script>");
  });
});

// ─── Color validation ──────────────────────────────────────────────────────────

describe("createBadgeSvg — color validation", () => {
  it("accepts valid 6-digit hex colours", () => {
    const svg = createBadgeSvg("l", "v", "#4c1d95");
    expect(svg).toContain('fill="#4c1d95"');
  });

  it("accepts valid 3-digit hex colours", () => {
    const svg = createBadgeSvg("l", "v", "#4c1");
    expect(svg).toContain('fill="#4c1"');
  });

  it("falls back to #999 for non-hex color strings", () => {
    // Prevent CSS injection via color parameter
    const svg = createBadgeSvg("l", "v", "red; background: url(evil)");
    expect(svg).toContain('fill="#999"');
    expect(svg).not.toContain("url(evil)");
  });

  it("falls back to #999 for empty color string", () => {
    const svg = createBadgeSvg("l", "v", "");
    expect(svg).toContain('fill="#999"');
  });

  it("falls back to #999 for color with script injection", () => {
    const svg = createBadgeSvg("l", "v", "#fff\"><script>alert(1)</script>");
    expect(svg).toContain('fill="#999"');
    expect(svg).not.toContain("<script>");
  });
});

// ─── Edge cases ───────────────────────────────────────────────────────────────

describe("createBadgeSvg — edge cases", () => {
  it("handles empty label and value", () => {
    const svg = createBadgeSvg("", "", "#999");
    expect(svg).toContain("<svg");
    expect(svg).toContain("</svg>");
  });

  it("handles very long label (truncation not enforced at SVG level)", () => {
    const long = "a".repeat(1000);
    const svg = createBadgeSvg(long, "ok", "#4c1");
    // Must not throw and must produce valid SVG
    expect(svg).toContain("</svg>");
  });

  it("produces different colours for different score ranges", () => {
    const good   = createBadgeSvg("l", "v", "#4c1");
    const warn   = createBadgeSvg("l", "v", "#dfb317");
    const poor   = createBadgeSvg("l", "v", "#fe7d37");
    const crit   = createBadgeSvg("l", "v", "#e05d44");
    expect(good).toContain("#4c1");
    expect(warn).toContain("#dfb317");
    expect(poor).toContain("#fe7d37");
    expect(crit).toContain("#e05d44");
  });
});
