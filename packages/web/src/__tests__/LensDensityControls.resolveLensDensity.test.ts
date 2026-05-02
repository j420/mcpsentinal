import { describe, expect, it } from "vitest";
// Imported from lib/ (server-callable). Previously imported from the
// "use client" controls module — moved during the digest-1244316665 fix
// because Next 15 forbids server components from invoking functions
// exported from a "use client" module.
import { resolveLensDensity } from "@/lib/lens-density";

describe("resolveLensDensity (server-side parser)", () => {
  it("returns story+briefing defaults when searchParams is undefined", () => {
    expect(resolveLensDensity(undefined)).toEqual({
      lens: "story",
      density: "briefing",
    });
  });

  it("returns story+briefing defaults when neither param is set", () => {
    expect(resolveLensDensity({})).toEqual({
      lens: "story",
      density: "briefing",
    });
  });

  it("parses each valid lens value", () => {
    expect(resolveLensDensity({ lens: "story" }).lens).toBe("story");
    expect(resolveLensDensity({ lens: "evidence" }).lens).toBe("evidence");
    expect(resolveLensDensity({ lens: "compliance" }).lens).toBe("compliance");
    expect(resolveLensDensity({ lens: "audit" }).lens).toBe("audit");
  });

  it("parses each valid density value", () => {
    expect(resolveLensDensity({ view: "briefing" }).density).toBe("briefing");
    expect(resolveLensDensity({ view: "dossier" }).density).toBe("dossier");
    expect(resolveLensDensity({ view: "forensic" }).density).toBe("forensic");
  });

  it("falls back to story when lens is unknown / malformed", () => {
    // (Note: `compliance` USED to be invalid; promoted to a valid lens
    // in commit adding the Compliance lens. The validation here covers
    // truly bad inputs only.)
    expect(resolveLensDensity({ lens: "future_lens_v9" }).lens).toBe("story");
    expect(resolveLensDensity({ lens: "" }).lens).toBe("story");
    expect(resolveLensDensity({ lens: "STORY" }).lens).toBe("story"); // case-sensitive
    expect(resolveLensDensity({ lens: "../etc/passwd" }).lens).toBe("story");
  });

  it("falls back to briefing when density is unknown / malformed", () => {
    expect(resolveLensDensity({ view: "compact" }).density).toBe("briefing");
    expect(resolveLensDensity({ view: "" }).density).toBe("briefing");
    expect(resolveLensDensity({ view: "BRIEFING" }).density).toBe("briefing");
  });

  it("uses the first element of array params (Next searchParams shape)", () => {
    expect(
      resolveLensDensity({ lens: ["audit", "evidence"], view: ["forensic"] }),
    ).toEqual({ lens: "audit", density: "forensic" });
  });

  it("returns lens + density independently — bad lens does not invalidate density", () => {
    expect(
      resolveLensDensity({ lens: "garbage", view: "forensic" }),
    ).toEqual({ lens: "story", density: "forensic" });
  });
});
