import { beforeEach, describe, expect, it } from "vitest";

import {
  __clearRendererRegistry,
  getAllRenderers,
  getRenderer,
  registerRenderer,
} from "../render/types.js";
import type {
  ComplianceReportRenderer,
  RendererFormat,
} from "../render/types.js";
import type { SignedComplianceReport } from "../types.js";

function fakeRenderer(
  format: RendererFormat,
  payload: string,
): ComplianceReportRenderer {
  return {
    format,
    contentType: `application/${format}`,
    filenameSuffix: format,
    render(_signed: SignedComplianceReport) {
      return payload;
    },
  };
}

describe("renderer registry", () => {
  beforeEach(() => {
    __clearRendererRegistry();
  });

  it("register / get round-trips", () => {
    const r = fakeRenderer("json", '{"ok":true}');
    registerRenderer("json", "eu_ai_act", r);
    expect(getRenderer("json", "eu_ai_act")).toBe(r);
  });

  it("returns undefined for unregistered (format, framework) pairs", () => {
    expect(getRenderer("pdf", "owasp_mcp")).toBeUndefined();
  });

  it("allows independent registration per (format, framework)", () => {
    registerRenderer("json", "eu_ai_act", fakeRenderer("json", "a"));
    registerRenderer("html", "eu_ai_act", fakeRenderer("html", "b"));
    registerRenderer("json", "iso_27001", fakeRenderer("json", "c"));
    expect(getAllRenderers()).toHaveLength(3);
    expect(getRenderer("json", "eu_ai_act")?.render({} as SignedComplianceReport)).toBe("a");
    expect(getRenderer("html", "eu_ai_act")?.render({} as SignedComplianceReport)).toBe("b");
    expect(getRenderer("json", "iso_27001")?.render({} as SignedComplianceReport)).toBe("c");
  });

  it("rejects renderers whose format field disagrees with the registration format", () => {
    const liar: ComplianceReportRenderer = {
      format: "pdf",
      contentType: "application/pdf",
      filenameSuffix: "pdf",
      render: () => Buffer.alloc(0),
    };
    expect(() => registerRenderer("json", "eu_ai_act", liar)).toThrow(/format mismatch/);
  });

  it("overwrites existing registration for the same (format, framework)", () => {
    const first = fakeRenderer("json", "first");
    const second = fakeRenderer("json", "second");
    registerRenderer("json", "maestro", first);
    registerRenderer("json", "maestro", second);
    expect(getRenderer("json", "maestro")).toBe(second);
  });
});
