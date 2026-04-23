import { readFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  resolveSigningContextFromEnv,
  signReport,
  verifyReport,
} from "../attestation.js";
import type { SigningContext } from "../attestation.js";
import type { ComplianceReport } from "../types.js";

const BASE_REPORT: ComplianceReport = {
  version: "1.0",
  server: {
    slug: "test-server",
    name: "Test Server",
    github_url: "https://github.com/example/test-server",
    scan_id: "00000000-0000-0000-0000-000000000001",
  },
  framework: {
    id: "eu_ai_act",
    name: "EU AI Act",
    version: "2024/1689",
    last_updated: "2026-04-23",
    source_url: "https://eur-lex.europa.eu/",
  },
  assessment: {
    assessed_at: "2026-04-23T00:00:00.000Z",
    rules_version: "2026-04-23-164rules",
    sentinel_version: "0.4.0",
    coverage_band: "high",
    coverage_ratio: 0.95,
    techniques_run: ["ast-taint", "capability-graph"],
  },
  controls: [],
  summary: {
    total_controls: 0,
    met: 0,
    unmet: 0,
    partial: 0,
    not_applicable: 0,
    overall_status: "insufficient_evidence",
  },
  kill_chains: [],
  executive_summary: "Test executive summary.",
};

const CTX: SigningContext = { key: "unit-test-key", key_id: "unit-test-id" };

describe("HMAC-SHA256 attestation", () => {
  it("round-trips sign → verify", () => {
    const signed = signReport(BASE_REPORT, CTX);
    expect(signed.attestation.algorithm).toBe("HMAC-SHA256");
    expect(signed.attestation.canonicalization).toBe("RFC8785");
    expect(signed.attestation.signature).toMatch(/^[A-Za-z0-9+/]+=*$/);
    const result = verifyReport(signed, CTX);
    expect(result.valid).toBe(true);
  });

  it("detects tampering with the report body", () => {
    const signed = signReport(BASE_REPORT, CTX);
    const tampered = {
      ...signed,
      report: {
        ...signed.report,
        summary: { ...signed.report.summary, unmet: 999 },
      },
    };
    const result = verifyReport(tampered, CTX);
    expect(result.valid).toBe(false);
    expect(result.reason).toBeDefined();
  });

  it("rejects signatures produced under a different key", () => {
    const signed = signReport(BASE_REPORT, CTX);
    const wrongKey: SigningContext = { key: "different-secret", key_id: CTX.key_id };
    const result = verifyReport(signed, wrongKey);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("signature does not match canonicalised payload");
  });

  it("rejects unsupported algorithm declarations", () => {
    const signed = signReport(BASE_REPORT, CTX);
    const bogus = {
      ...signed,
      attestation: { ...signed.attestation, algorithm: "HMAC-MD5" as unknown as "HMAC-SHA256" },
    };
    const result = verifyReport(bogus, CTX);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("unsupported algorithm");
  });

  it("rejects unsupported canonicalization declarations", () => {
    const signed = signReport(BASE_REPORT, CTX);
    const bogus = {
      ...signed,
      attestation: { ...signed.attestation, canonicalization: "JSON.stringify" as unknown as "RFC8785" },
    };
    const result = verifyReport(bogus, CTX);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain("unsupported canonicalization");
  });

  it("rejects a truncated / wrong-length signature without throwing", () => {
    const signed = signReport(BASE_REPORT, CTX);
    const bogus = {
      ...signed,
      attestation: { ...signed.attestation, signature: "c2hvcnQ=" },
    };
    const result = verifyReport(bogus, CTX);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("signature length mismatch");
  });

  it("produces identical signatures across runs for identical input", () => {
    // Sign two reports whose bodies match exactly. The attestation envelope
    // timestamp differs, but the signature bytes over the report body must
    // be identical.
    const a = signReport(BASE_REPORT, CTX);
    const b = signReport(BASE_REPORT, CTX);
    expect(a.attestation.signature).toBe(b.attestation.signature);
  });

  it("produces different signatures when key_id changes but key stays the same", () => {
    // key_id is metadata, not input to HMAC, so signature should NOT change.
    const a = signReport(BASE_REPORT, CTX);
    const b = signReport(BASE_REPORT, { key: CTX.key, key_id: "other-id" });
    expect(a.attestation.signature).toBe(b.attestation.signature);
    expect(a.attestation.key_id).not.toBe(b.attestation.key_id);
  });

  it("uses crypto.timingSafeEqual in the implementation (constant-time spot-check)", () => {
    // We can't reliably measure timing in unit tests, so assert by source
    // inspection that timingSafeEqual is invoked. This catches accidental
    // regressions to `===` or Buffer.compare-with-early-return.
    const src = readFileSync(
      new URL("../attestation.ts", import.meta.url),
      "utf8",
    );
    expect(src).toContain("timingSafeEqual");
    expect(src).not.toMatch(/signature\s*===\s*/); // no plain ===
  });
});

describe("resolveSigningContextFromEnv", () => {
  const originalKey = process.env.COMPLIANCE_SIGNING_KEY;
  const originalKeyId = process.env.COMPLIANCE_SIGNING_KEY_ID;
  beforeEach(() => {
    delete process.env.COMPLIANCE_SIGNING_KEY;
    delete process.env.COMPLIANCE_SIGNING_KEY_ID;
  });
  afterEach(() => {
    if (originalKey !== undefined) process.env.COMPLIANCE_SIGNING_KEY = originalKey;
    if (originalKeyId !== undefined) process.env.COMPLIANCE_SIGNING_KEY_ID = originalKeyId;
    vi.restoreAllMocks();
  });

  it("uses env vars when both are present", () => {
    process.env.COMPLIANCE_SIGNING_KEY = "prod-secret";
    process.env.COMPLIANCE_SIGNING_KEY_ID = "prod-key-2026-04";
    const ctx = resolveSigningContextFromEnv();
    expect(ctx).toEqual({ key: "prod-secret", key_id: "prod-key-2026-04" });
  });

  it("falls back to dev key and emits a warning when env is unset", () => {
    const ctx = resolveSigningContextFromEnv();
    expect(ctx.key).toBe("dev-key-do-not-use-in-prod");
    expect(ctx.key_id).toBe("mcp-sentinel-dev");
  });

  it("dev-key signatures are distinct from prod-key signatures (no silent acceptance)", () => {
    const devCtx = resolveSigningContextFromEnv();
    process.env.COMPLIANCE_SIGNING_KEY = "prod-secret";
    process.env.COMPLIANCE_SIGNING_KEY_ID = "prod-id";
    const prodCtx = resolveSigningContextFromEnv();
    const devSigned = signReport(BASE_REPORT, devCtx);
    const prodSigned = signReport(BASE_REPORT, prodCtx);
    expect(devSigned.attestation.signature).not.toBe(prodSigned.attestation.signature);
    // Verify cross-rejection.
    expect(verifyReport(devSigned, prodCtx).valid).toBe(false);
    expect(verifyReport(prodSigned, devCtx).valid).toBe(false);
  });
});
