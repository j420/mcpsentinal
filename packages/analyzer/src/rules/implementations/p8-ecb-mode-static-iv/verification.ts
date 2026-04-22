/**
 * P8 verification-step builders. Each step carries a structured Location
 * target.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { P8Fact } from "./gather.js";

export function stepInspectCryptoPrimitive(fact: P8Fact): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open ${fact.file} at line ${fact.line}:${fact.col} and confirm the cryptographic ` +
      `primitive matches the finding's variant (${fact.variant}). For ECB detection, ` +
      `verify the cipher spec string actually reaches \`crypto.createCipheriv\` / ` +
      `\`createCipher\`. For static IV, verify the binding is consumed by a cipher / ` +
      `signing routine. For Math.random() in crypto context, verify the random value ` +
      `feeds a key / IV / nonce / token.`,
    target: fact.location,
    expected_observation: fact.description,
  };
}

export function stepCheckCSPRNGPresence(fact: P8Fact): VerificationStep {
  const target: Location = { kind: "source", file: fact.file, line: 1, col: 1 };
  return {
    step_type: "inspect-source",
    instruction:
      fact.csprngAvailableNearby
        ? `Read the top of ${fact.file} and confirm a CSPRNG (crypto.randomBytes / ` +
          `getRandomValues / randomUUID / randomFillSync / webcrypto) IS available. ` +
          `The developer has the primitive but chose the weak path at line ${fact.line}.`
        : `Read the top of ${fact.file} and confirm NO CSPRNG is imported. The gap is ` +
          `absolute, not partial.`,
    target,
    expected_observation:
      fact.csprngAvailableNearby
        ? `At least one CSPRNG usage found in this file.`
        : `No crypto.randomBytes / getRandomValues / webcrypto usage in this file.`,
  };
}

export function stepInspectReachability(fact: P8Fact): VerificationStep {
  return {
    step_type: "trace-flow",
    instruction:
      `Confirm the flagged code is reachable in production. A call guarded by ` +
      `\`if (process.env.NODE_ENV === "test")\` that tree-shaking removes does not ` +
      `need the finding, but one inside a hot-path handler does. Walk the CFG from ` +
      `module entry to this location.`,
    target: fact.location,
    expected_observation:
      `The flagged construct executes on the normal control-flow path (not dead code ` +
      `behind a test-only flag).`,
  };
}
