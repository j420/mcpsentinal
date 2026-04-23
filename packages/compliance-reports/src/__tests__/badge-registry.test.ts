import { beforeEach, describe, expect, it } from "vitest";

import {
  __clearBadgeRegistry,
  getBadge,
  registerBadge,
} from "../badges/types.js";
import type { ComplianceBadgeRenderer } from "../badges/types.js";
import type { ComplianceReport, FrameworkId, SignedComplianceReport } from "../types.js";

function fakeBadge(framework: FrameworkId, svg: string): ComplianceBadgeRenderer {
  return {
    framework,
    render(_r: ComplianceReport, _a: SignedComplianceReport["attestation"]) {
      return svg;
    },
  };
}

describe("badge registry", () => {
  beforeEach(() => {
    __clearBadgeRegistry();
  });

  it("register / get round-trips", () => {
    const b = fakeBadge("eu_ai_act", "<svg></svg>");
    registerBadge("eu_ai_act", b);
    expect(getBadge("eu_ai_act")).toBe(b);
  });

  it("returns undefined for unregistered frameworks", () => {
    expect(getBadge("mitre_atlas")).toBeUndefined();
  });

  it("rejects badges whose framework field disagrees with the registration", () => {
    const liar: ComplianceBadgeRenderer = {
      framework: "iso_27001",
      render: () => "<svg/>",
    };
    expect(() => registerBadge("eu_ai_act", liar)).toThrow(/framework mismatch/);
  });

  it("overwrites existing registration for the same framework", () => {
    const first = fakeBadge("owasp_mcp", "<a/>");
    const second = fakeBadge("owasp_mcp", "<b/>");
    registerBadge("owasp_mcp", first);
    registerBadge("owasp_mcp", second);
    expect(getBadge("owasp_mcp")).toBe(second);
  });
});
