import { beforeEach, describe, expect, it } from "vitest";

import { __clearBadgeRegistry, getBadge } from "../badges/types.js";
import {
  SVG_BADGE_RENDERER,
  __TESTING,
} from "../badges/svg-renderer.js";
import {
  registerAllBadges,
  __resetRegistrationGuard,
} from "../badges/register-all.js";
import type {
  ComplianceReport,
  FrameworkId,
  OverallStatus,
  SignedComplianceReport,
} from "../types.js";
import { FRAMEWORK_IDS } from "../types.js";

const FIXED_ATTESTATION: SignedComplianceReport["attestation"] = {
  algorithm: "HMAC-SHA256",
  signature: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  key_id: "mcp-sentinel-test",
  signed_at: "2026-04-23T00:00:00.000Z",
  signer: "mcp-sentinel/v1",
  canonicalization: "RFC8785",
};

function makeReport(
  framework: FrameworkId,
  status: OverallStatus,
  counts: { met: number; unmet: number; partial: number; not_applicable: number },
): ComplianceReport {
  return {
    version: "1.0",
    server: {
      slug: "demo",
      name: "Demo Server",
      github_url: null,
      scan_id: "00000000-0000-0000-0000-0000000000aa",
    },
    framework: {
      id: framework,
      name: framework,
      version: "1",
      last_updated: "2026-04-23",
      source_url: "https://example.com",
    },
    assessment: {
      assessed_at: "2026-04-23T00:00:00.000Z",
      rules_version: "2026-04-23",
      sentinel_version: "0.4.0",
      coverage_band: "high",
      coverage_ratio: 0.9,
      techniques_run: ["ast-taint"],
    },
    controls: [],
    summary: {
      total_controls: counts.met + counts.unmet + counts.partial + counts.not_applicable,
      ...counts,
      overall_status: status,
    },
    kill_chains: [],
    executive_summary: "Synthetic report for badge tests.",
  };
}

describe("SVG_BADGE_RENDERER — output shape", () => {
  it("produces a well-formed SVG with XML prolog and svg root", () => {
    const report = makeReport("eu_ai_act", "compliant", {
      met: 5, unmet: 0, partial: 0, not_applicable: 1,
    });
    const svg = SVG_BADGE_RENDERER.render(report, FIXED_ATTESTATION);
    expect(svg).toMatch(/^<\?xml version="1\.0"/);
    expect(svg).toContain("<svg");
    expect(svg).toContain("</svg>");
    expect(svg).toContain('xmlns="http://www.w3.org/2000/svg"');
  });

  it("embeds the attestation as an XML comment", () => {
    const report = makeReport("iso_27001", "compliant", {
      met: 3, unmet: 0, partial: 0, not_applicable: 0,
    });
    const svg = SVG_BADGE_RENDERER.render(report, FIXED_ATTESTATION);
    expect(svg).toContain("<!-- attestation:");
    expect(svg).toContain(`signature=${FIXED_ATTESTATION.signature}`);
    expect(svg).toContain(`key_id=${FIXED_ATTESTATION.key_id}`);
    expect(svg).toContain(`signed_at=${FIXED_ATTESTATION.signed_at}`);
    expect(svg).toContain("algorithm=HMAC-SHA256");
  });

  it("includes aria-label for accessibility", () => {
    const report = makeReport("owasp_mcp", "compliant", {
      met: 10, unmet: 0, partial: 0, not_applicable: 0,
    });
    const svg = SVG_BADGE_RENDERER.render(report, FIXED_ATTESTATION);
    expect(svg).toMatch(/aria-label="[^"]+"/);
  });

  it("does not contain Date.now or Math.random outputs (determinism)", () => {
    const report = makeReport("maestro", "compliant", {
      met: 7, unmet: 0, partial: 0, not_applicable: 0,
    });
    const a = SVG_BADGE_RENDERER.render(report, FIXED_ATTESTATION);
    const b = SVG_BADGE_RENDERER.render(report, FIXED_ATTESTATION);
    expect(a).toBe(b);
  });
});

describe("SVG_BADGE_RENDERER — status colors", () => {
  it("uses green for compliant", () => {
    const report = makeReport("eu_ai_act", "compliant", {
      met: 5, unmet: 0, partial: 0, not_applicable: 0,
    });
    const svg = SVG_BADGE_RENDERER.render(report, FIXED_ATTESTATION);
    expect(svg).toContain(__TESTING.STATUS_COLORS.compliant);
    expect(svg).toContain("compliant");
  });

  it("uses red for non_compliant", () => {
    const report = makeReport("eu_ai_act", "non_compliant", {
      met: 2, unmet: 3, partial: 0, not_applicable: 0,
    });
    const svg = SVG_BADGE_RENDERER.render(report, FIXED_ATTESTATION);
    expect(svg).toContain(__TESTING.STATUS_COLORS.non_compliant);
    expect(svg).toContain("non-compliant");
  });

  it("uses amber for partially_compliant and shows X/Y met", () => {
    const report = makeReport("eu_ai_act", "partially_compliant", {
      met: 3, unmet: 0, partial: 2, not_applicable: 1,
    });
    const svg = SVG_BADGE_RENDERER.render(report, FIXED_ATTESTATION);
    expect(svg).toContain(__TESTING.STATUS_COLORS.partially_compliant);
    // total = 6, not_applicable = 1, assessed = 5, met = 3 → "3/5 met"
    expect(svg).toContain("3/5 met");
  });

  it("uses gray for insufficient_evidence", () => {
    const report = makeReport("eu_ai_act", "insufficient_evidence", {
      met: 0, unmet: 0, partial: 0, not_applicable: 5,
    });
    const svg = SVG_BADGE_RENDERER.render(report, FIXED_ATTESTATION);
    expect(svg).toContain(__TESTING.STATUS_COLORS.insufficient_evidence);
    expect(svg).toContain("insufficient evidence");
  });
});

describe("SVG_BADGE_RENDERER — framework accent colors", () => {
  // Drives each of the 7 frameworks through the renderer and asserts the
  // correct accent color + short name appear in the output.
  const cases: Array<[FrameworkId, string, string]> = [
    ["eu_ai_act", "#003399", "EU AI Act"],
    ["iso_27001", "#0068b7", "ISO 27001"],
    ["owasp_mcp", "#000000", "OWASP MCP"],
    ["owasp_asi", "#000000", "OWASP ASI"],
    ["cosai_mcp", "#1976d2", "CoSAI"],
    ["maestro", "#5b21b6", "MAESTRO"],
    ["mitre_atlas", "#dc2626", "MITRE ATLAS"],
  ];

  for (const [framework, color, shortName] of cases) {
    it(`${framework} renders with accent ${color} and short name "${shortName}"`, () => {
      const report = makeReport(framework, "compliant", {
        met: 1, unmet: 0, partial: 0, not_applicable: 0,
      });
      const svg = SVG_BADGE_RENDERER.render(report, FIXED_ATTESTATION);
      expect(svg).toContain(color);
      expect(svg).toContain(shortName);
    });
  }
});

describe("registerAllBadges — 7-framework wiring", () => {
  beforeEach(() => {
    __clearBadgeRegistry();
    __resetRegistrationGuard();
  });

  it("registers one badge per framework id", () => {
    registerAllBadges();
    for (const id of FRAMEWORK_IDS) {
      const b = getBadge(id);
      expect(b, `badge for ${id}`).toBeDefined();
      expect(b?.framework).toBe(id);
    }
  });

  it("is idempotent — calling twice does not throw", () => {
    registerAllBadges();
    expect(() => registerAllBadges()).not.toThrow();
  });

  it("registered badges render correctly via the registry", () => {
    registerAllBadges();
    const badge = getBadge("cosai_mcp");
    expect(badge).toBeDefined();
    const report = makeReport("cosai_mcp", "compliant", {
      met: 1, unmet: 0, partial: 0, not_applicable: 0,
    });
    const svg = badge!.render(report, FIXED_ATTESTATION);
    expect(svg).toContain("CoSAI");
    expect(svg).toContain("#1976d2");
  });
});

describe("SVG_BADGE_RENDERER — escaping", () => {
  it("escapes ampersands and special chars in attestation fields", () => {
    const tricky: SignedComplianceReport["attestation"] = {
      ...FIXED_ATTESTATION,
      signer: "evil<&>\"'",
    };
    const report = makeReport("eu_ai_act", "compliant", {
      met: 1, unmet: 0, partial: 0, not_applicable: 0,
    });
    const svg = SVG_BADGE_RENDERER.render(report, tricky);
    // The attacker-controlled signer should be XML-escaped inside the comment.
    expect(svg).not.toContain("evil<&>");
    expect(svg).toContain("evil&lt;&amp;&gt;");
  });
});
