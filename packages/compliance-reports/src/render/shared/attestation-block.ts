import type { SignedComplianceReport } from "../../types.js";

/**
 * Canonical verification-instructions text. Embedded verbatim in the
 * HTML and PDF attestation panel. Written as a literal so regulators
 * can paste it into a terminal unmodified.
 */
export function verificationInstructions(signed: SignedComplianceReport): string[] {
  return [
    "To verify this report:",
    "  1. Extract the report body (everything except the .attestation field).",
    "  2. Canonicalize the body via RFC 8785 (JCS).",
    `  3. Compute HMAC-SHA256 with the signing key for key_id "${signed.attestation.key_id}".`,
    "  4. Base64-encode the result and compare with the signature above.",
  ];
}

/** Fields shown in the attestation block, in display order. */
export interface AttestationField {
  label: string;
  value: string;
  monospace: boolean;
}

export function attestationFields(signed: SignedComplianceReport): AttestationField[] {
  return [
    { label: "Algorithm", value: signed.attestation.algorithm, monospace: true },
    { label: "Key ID", value: signed.attestation.key_id, monospace: true },
    { label: "Signer", value: signed.attestation.signer, monospace: true },
    { label: "Signed at", value: signed.attestation.signed_at, monospace: true },
    { label: "Canonicalization", value: signed.attestation.canonicalization, monospace: true },
  ];
}
