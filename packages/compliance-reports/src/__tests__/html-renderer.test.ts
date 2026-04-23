import { Parser } from "htmlparser2";
import { describe, expect, it } from "vitest";

import { getFramework } from "../frameworks/index.js";
import { htmlRenderer } from "../render/html-renderer.js";
import { FRAMEWORK_IDS } from "../types.js";
import type { FrameworkId } from "../types.js";
import { makeSyntheticSignedReport } from "./renderer-fixtures.js";

function parseHtml(html: string): { openTags: string[]; closeTags: string[]; errors: Error[] } {
  const openTags: string[] = [];
  const closeTags: string[] = [];
  const errors: Error[] = [];
  const parser = new Parser(
    {
      onopentag(name) { openTags.push(name); },
      onclosetag(name) { closeTags.push(name); },
      onerror(err) { errors.push(err); },
    },
    { recognizeSelfClosing: true, decodeEntities: true },
  );
  parser.write(html);
  parser.end();
  return { openTags, closeTags, errors };
}

describe("htmlRenderer", () => {
  it("renders a well-formed document for eu_ai_act", () => {
    const signed = makeSyntheticSignedReport("eu_ai_act");
    const html = htmlRenderer.render(signed) as string;
    expect(typeof html).toBe("string");
    expect(html.startsWith("<!doctype html>")).toBe(true);
    expect(html).toContain("EU AI Act");
    expect(html).toContain("test-server");
    expect(html).toContain(signed.attestation.signature);
    expect(html).toContain("DRAFT");
    expect(html).toContain("Assessment of Test Server against EU AI Act");
  });

  it("renders a well-formed document for owasp_mcp", () => {
    const signed = makeSyntheticSignedReport("owasp_mcp");
    const html = htmlRenderer.render(signed) as string;
    expect(html.startsWith("<!doctype html>")).toBe(true);
    expect(html).toContain(getFramework("owasp_mcp").name);
    expect(html).toContain("test-server");
    expect(html).toContain(signed.attestation.signature);
    expect(html).toContain("DRAFT");
    expect(html).toContain("Executive summary");
  });

  it.each(FRAMEWORK_IDS as readonly FrameworkId[])("includes the framework name for %s", (framework_id) => {
    const signed = makeSyntheticSignedReport(framework_id);
    const html = htmlRenderer.render(signed) as string;
    expect(html).toContain(getFramework(framework_id).name);
    expect(html).toContain(`data-framework-id="${framework_id}"`);
  });

  it("produces parseable HTML with no parser errors", () => {
    const signed = makeSyntheticSignedReport("iso_27001");
    const html = htmlRenderer.render(signed) as string;
    const { openTags, closeTags, errors } = parseHtml(html);
    expect(errors).toEqual([]);
    // Non-void elements must balance. The parser tracks both; we require that
    // every opener has a matching closer for elements that require one.
    // htmlparser2 emits synthetic closers for implicit cases, so open and
    // close counts should match for body/head/html tags at minimum.
    const count = (arr: string[], tag: string) => arr.filter((t) => t === tag).length;
    for (const tag of ["html", "head", "body", "main", "section", "table", "thead", "tbody", "dl"]) {
      expect(count(openTags, tag)).toBe(count(closeTags, tag));
    }
  });

  it("HTML-escapes user-supplied server names to prevent XSS", () => {
    const signed = makeSyntheticSignedReport("eu_ai_act", {
      serverName: "<script>alert(1)</script>",
      serverSlug: "malicious",
    });
    const html = htmlRenderer.render(signed) as string;
    expect(html).not.toContain("<script>alert(1)</script>");
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
  });

  it("is byte-deterministic for identical input", () => {
    const a = makeSyntheticSignedReport("cosai_mcp");
    const b = makeSyntheticSignedReport("cosai_mcp");
    expect(htmlRenderer.render(a)).toBe(htmlRenderer.render(b));
  });
});
