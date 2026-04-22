/**
 * P8 — Insecure Cryptographic Mode or Static IV/Nonce (v2)
 *
 * One finding per AST fact. Three variants: ecb_mode, static_iv,
 * math_random_crypto. Confidence cap 0.80 — room for reachability
 * uncertainty and downstream rewrites the static analyzer cannot see.
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder, type EvidenceChain } from "../../../evidence.js";
import { gatherP8, type P8Fact } from "./gather.js";
import {
  stepInspectCryptoPrimitive,
  stepCheckCSPRNGPresence,
  stepInspectReachability,
} from "./verification.js";

const RULE_ID = "P8";
const RULE_NAME = "Insecure Cryptographic Mode or Static IV/Nonce";
const OWASP = "MCP07-insecure-config" as const;
const MITRE = "T1600";
const CONFIDENCE_CAP = 0.8;

const REMEDIATION =
  "Use authenticated encryption modes (AES-256-GCM, ChaCha20-Poly1305). Generate IVs " +
  "and nonces with a CSPRNG: `crypto.randomBytes(16)` in Node.js, " +
  "`crypto.getRandomValues(new Uint8Array(16))` in the browser. Never reuse a " +
  "(key, nonce) pair. Never use Math.random() for any cryptographic value. Derive " +
  "keys via Argon2id / scrypt / PBKDF2 with random salts. Prefer libraries that " +
  "enforce these defaults (libsodium, @noble/ciphers) over hand-rolled primitives.";

class EcbStaticIvRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherP8(context);
    if (gathered.facts.length === 0) return [];
    return gathered.facts.map((fact) => this.buildFinding(fact));
  }

  private buildFinding(fact: P8Fact): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: fact.location,
        observed: fact.observed,
        rationale: buildSourceRationale(fact),
      })
      .sink({
        sink_type: "credential-exposure",
        location: fact.location,
        observed: `Weak cryptography primitive: ${fact.description}`,
      })
      .mitigation({
        mitigation_type: "sanitizer-function",
        present: fact.csprngAvailableNearby,
        location: { kind: "source", file: fact.file, line: 1, col: 1 },
        detail: fact.csprngAvailableNearby
          ? `A CSPRNG (crypto.randomBytes / getRandomValues / randomUUID) IS imported in ` +
            `this file — the developer has access to the correct primitive but chose the ` +
            `weak path at line ${fact.line}. Confidence reduced; finding NOT suppressed.`
          : `No CSPRNG usage observed in this file — full gap.`,
      })
      .impact({
        impact_type: "data-exfiltration",
        scope: "user-data",
        exploitability: fact.variant === "math_random_crypto" ? "moderate" : "complex",
        scenario: buildImpactScenario(fact),
      })
      .factor("crypto_misuse_pattern", 0.08, fact.description)
      .factor(
        fact.csprngAvailableNearby ? "csprng_available_nearby" : "csprng_absent",
        fact.csprngAvailableNearby ? -0.1 : 0.05,
        fact.csprngAvailableNearby
          ? `A secure RNG primitive is used elsewhere in this file.`
          : `No CSPRNG usage detected — the author does not appear to know the correct primitive.`,
      )
      .factor("crypto_variant", 0.02, `Variant: ${fact.variant}`)
      .reference({
        id: "CWE-327",
        title: "CWE-327 — Use of a Broken or Risky Cryptographic Algorithm",
        url: "https://cwe.mitre.org/data/definitions/327.html",
        relevance:
          fact.variant === "ecb_mode"
            ? "ECB mode is the canonical CWE-327 example — plaintext equality leaks " +
              "through to ciphertext, enabling pattern recognition attacks without " +
              "breaking the cipher itself."
            : fact.variant === "static_iv"
              ? "Static/predictable IV is CWE-329 and CWE-1204. CBC mode with static IV " +
                "permits chosen-plaintext attacks; CTR/GCM with reused IV yields keystream " +
                "recovery and full plaintext disclosure."
              : "Math.random() as a crypto source is CWE-338 — predictable PRNG output " +
                "enables ECDSA nonce-reuse private-key extraction (SlowMist web3 incidents) " +
                "and session/token prediction.",
      })
      .verification(stepInspectCryptoPrimitive(fact))
      .verification(stepCheckCSPRNGPresence(fact))
      .verification(stepInspectReachability(fact));

    const chain = capConfidence(builder.build(), CONFIDENCE_CAP);

    return {
      rule_id: RULE_ID,
      severity: "high",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain,
    };
  }
}

function buildSourceRationale(fact: P8Fact): string {
  switch (fact.variant) {
    case "ecb_mode":
      return (
        `${fact.description}. ECB mode preserves plaintext equality in the ciphertext; ` +
        `identical plaintext blocks produce identical ciphertext blocks, leaking ` +
        `structural information without breaking the cipher key (NIST SP 800-38A).`
      );
    case "static_iv":
      return (
        `${fact.description}. A constant IV / nonce turns a secure mode into a broken ` +
        `one: CBC allows chosen-plaintext recovery, CTR/GCM collapse into two-time-pad ` +
        `attacks on the first reused nonce (CWE-329 / CWE-1204).`
      );
    case "math_random_crypto":
      return (
        `${fact.description}. Math.random() is not a CSPRNG — its V8 implementation is a ` +
        `public 128-bit XorShift128+ state recoverable from a small number of outputs ` +
        `(Cardis 2015). Using it to derive keys, IVs, or nonces enables immediate ` +
        `cryptographic bypass.`
      );
  }
}

function buildImpactScenario(fact: P8Fact): string {
  switch (fact.variant) {
    case "ecb_mode":
      return (
        `Attacker observes ciphertexts of user PII encrypted in ECB mode. Identical ` +
        `plaintext blocks (e.g. the same user's repeated field value) produce identical ` +
        `ciphertext blocks, allowing the attacker to recognise users across sessions ` +
        `without knowing the key.`
      );
    case "static_iv":
      return (
        `Two ciphertexts encrypted under the same (key, static_iv) pair collapse into a ` +
        `two-time pad: XORing them yields the XOR of the plaintexts, which recovers ` +
        `them with a crib-dragging attack in seconds. For GCM, a reused nonce also ` +
        `recovers the authentication key, defeating integrity entirely.`
      );
    case "math_random_crypto":
      return (
        `Math.random() state is recoverable from three to five successive outputs. Once ` +
        `recovered, the attacker predicts every future output — every subsequent IV, ` +
        `nonce, token, or derived key. For ECDSA with Math.random()-derived nonces, the ` +
        `attacker extracts the private key from two signatures in constant time ` +
        `(SlowMist 2022–2024 web3 incidents).`
      );
  }
}

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `P8 charter caps confidence at ${cap} — a per-binding reachability analysis ` +
      `could raise this in Phase 2. Today, code-path and downstream-rewrite ` +
      `uncertainty justify the cap.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new EcbStaticIvRule());

export { EcbStaticIvRule };
