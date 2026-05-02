import { createHmac, timingSafeEqual } from "node:crypto";
import pino from "pino";

import { canonicalize } from "./canonicalize.js";
import type {
  ComplianceReport,
  FindingReceipt,
  SignedComplianceReport,
  SignedFinding,
} from "./types.js";

const logger = pino({ name: "compliance-reports:attestation", level: "info" }, pino.destination(2));

/**
 * Symmetric signing context. The {@link key} is the raw HMAC secret and
 * MUST NEVER appear in the signed report. {@link key_id} is the public
 * identifier included in the attestation envelope so that verifiers know
 * which secret to look up.
 */
export interface SigningContext {
  key: string;
  key_id: string;
}

const SIGNER = "mcp-sentinel/v1";
const DEV_KEY = "dev-key-do-not-use-in-prod";
const DEV_KEY_ID = "mcp-sentinel-dev";

/**
 * Produce a signed compliance report. The signature covers exactly the
 * bytes produced by {@link canonicalize}, independent of the outer
 * attestation envelope. `signed_at` is stamped at call time and is NOT
 * covered by the signature (regulators rely on the wall-clock timestamp
 * that the signature was produced; mutating it after-the-fact would
 * invalidate the chain of custody, but that's a deployment control, not
 * a cryptographic one).
 */
export function signReport(report: ComplianceReport, ctx: SigningContext): SignedComplianceReport {
  const canonical = canonicalize(report);
  const hmac = createHmac("sha256", ctx.key);
  hmac.update(Buffer.from(canonical, "utf8"));
  const signature = hmac.digest("base64");
  return {
    report,
    attestation: {
      algorithm: "HMAC-SHA256",
      signature,
      key_id: ctx.key_id,
      signed_at: new Date().toISOString(),
      signer: SIGNER,
      canonicalization: "RFC8785",
    },
  };
}

/**
 * Recompute the HMAC over the canonicalised report body and compare it
 * to the provided signature in constant time. Returns `{ valid: false,
 * reason }` on mismatch or malformed input; never throws for caller
 * convenience on the HTTP path.
 */
export function verifyReport(
  signed: SignedComplianceReport,
  ctx: SigningContext,
): { valid: boolean; reason?: string } {
  if (signed.attestation.algorithm !== "HMAC-SHA256") {
    return { valid: false, reason: `unsupported algorithm: ${signed.attestation.algorithm}` };
  }
  if (signed.attestation.canonicalization !== "RFC8785") {
    return {
      valid: false,
      reason: `unsupported canonicalization: ${signed.attestation.canonicalization}`,
    };
  }
  const canonical = canonicalize(signed.report);
  const hmac = createHmac("sha256", ctx.key);
  hmac.update(Buffer.from(canonical, "utf8"));
  const expected = hmac.digest();
  let actual: Buffer;
  try {
    actual = Buffer.from(signed.attestation.signature, "base64");
  } catch {
    return { valid: false, reason: "signature is not valid base64" };
  }
  if (actual.length !== expected.length) {
    return { valid: false, reason: "signature length mismatch" };
  }
  // timingSafeEqual is constant-time; short-circuiting prefix comparison
  // is what we explicitly DO NOT want here.
  const ok = timingSafeEqual(actual, expected);
  return ok ? { valid: true } : { valid: false, reason: "signature does not match canonicalised payload" };
}

/**
 * Sign a single finding receipt. Mirrors {@link signReport}: the signature
 * covers exactly the bytes produced by {@link canonicalize} over `receipt`
 * (RFC 8785), independent of the outer attestation envelope. Auditors verify
 * by recomputing the canonical bytes locally and comparing the HMAC.
 *
 * The receipt is the auditor's offline-verifiable artifact: paired with the
 * public `key_id`, any third party with the corresponding HMAC secret can
 * confirm that this exact JSON was produced by this Sentinel deployment at
 * the stated `signed_at`. Useful for compliance packages that include a
 * subset of findings without the full ComplianceReport envelope.
 */
export function signFinding(receipt: FindingReceipt, ctx: SigningContext): SignedFinding {
  const canonical = canonicalize(receipt);
  const hmac = createHmac("sha256", ctx.key);
  hmac.update(Buffer.from(canonical, "utf8"));
  const signature = hmac.digest("base64");
  return {
    receipt,
    attestation: {
      algorithm: "HMAC-SHA256",
      signature,
      key_id: ctx.key_id,
      signed_at: new Date().toISOString(),
      signer: SIGNER,
      canonicalization: "RFC8785",
    },
  };
}

/**
 * Verify a per-finding receipt. Symmetric with {@link verifyReport}: rejects
 * unsupported algorithm/canonicalization, decodes the signature in base64,
 * and compares in constant time. Never throws.
 */
export function verifyFinding(
  signed: SignedFinding,
  ctx: SigningContext,
): { valid: boolean; reason?: string } {
  if (signed.attestation.algorithm !== "HMAC-SHA256") {
    return { valid: false, reason: `unsupported algorithm: ${signed.attestation.algorithm}` };
  }
  if (signed.attestation.canonicalization !== "RFC8785") {
    return {
      valid: false,
      reason: `unsupported canonicalization: ${signed.attestation.canonicalization}`,
    };
  }
  const canonical = canonicalize(signed.receipt);
  const hmac = createHmac("sha256", ctx.key);
  hmac.update(Buffer.from(canonical, "utf8"));
  const expected = hmac.digest();
  let actual: Buffer;
  try {
    actual = Buffer.from(signed.attestation.signature, "base64");
  } catch {
    return { valid: false, reason: "signature is not valid base64" };
  }
  if (actual.length !== expected.length) {
    return { valid: false, reason: "signature length mismatch" };
  }
  const ok = timingSafeEqual(actual, expected);
  return ok
    ? { valid: true }
    : { valid: false, reason: "signature does not match canonicalised receipt" };
}

/**
 * Resolve the signing context from process environment. Production
 * deployments MUST set both `COMPLIANCE_SIGNING_KEY` and
 * `COMPLIANCE_SIGNING_KEY_ID`. In development / CI we fall back to a
 * deterministic dev key and emit a warning — this guarantees dev
 * signatures are recognisably different from prod and never validate
 * against a prod key.
 */
export function resolveSigningContextFromEnv(): SigningContext {
  const key = process.env.COMPLIANCE_SIGNING_KEY;
  const keyId = process.env.COMPLIANCE_SIGNING_KEY_ID;
  if (key && keyId) {
    return { key, key_id: keyId };
  }
  logger.warn(
    "COMPLIANCE_SIGNING_KEY and/or COMPLIANCE_SIGNING_KEY_ID not set — using insecure dev key. DO NOT use for regulator-facing reports.",
  );
  return { key: DEV_KEY, key_id: DEV_KEY_ID };
}
