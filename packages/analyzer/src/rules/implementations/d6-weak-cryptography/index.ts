/**
 * D6 — Weak Cryptography Dependencies (v2)
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
import { gatherD6, type WeakCryptoSite } from "./gather.js";
import {
  stepCheckInstalledVersion,
  stepConsultCwe327,
  stepInspectManifest,
} from "./verification.js";

const RULE_ID = "D6";
const RULE_NAME = "Weak Cryptography Dependencies";
const OWASP = "MCP07-insecure-config" as const;
const MITRE: string | null = null;
const CONFIDENCE_CAP = 0.88;

const REMEDIATION =
  "Replace the weak-cryptography dependency. For version-gated entries (crypto-js <4.2.0, " +
  "node-forge <1.3.0, jsonwebtoken <9.0.0), upgrade to the safe minimum version. For " +
  "fundamentally broken primitives (MD5, SHA-1, RC4, DES) remove the library and re-implement " +
  "the operation on modern primitives (AES-GCM, ChaCha20-Poly1305, SHA-256/SHA-3, Argon2id). " +
  "For abandoned libraries (bcrypt-nodejs, pycrypto) migrate to the actively-maintained " +
  "equivalent (bcrypt / bcryptjs / pycryptodome).";

const REF_CWE_327 = {
  id: "CWE-327",
  title: "Use of a Broken or Risky Cryptographic Algorithm",
  url: "https://cwe.mitre.org/data/definitions/327.html",
  relevance:
    "CWE-327 is the canonical control D6 operationalises at dependency level. A project that " +
    "imports a library whose primary crypto primitive is broken is inheriting the CWE-327 " +
    "finding by transit.",
} as const;

class WeakCryptographyDependenciesRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { dependencies: true };
  readonly technique: AnalysisTechnique = "dependency-audit";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherD6(context);
    return gathered.sites.map((site) => this.buildFinding(site));
  }

  private buildFinding(site: WeakCryptoSite): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "external-content",
        location: site.dependencyLocation,
        observed:
          `Dependency ${site.ecosystem}:${site.name}@${site.version} matches a weak-cryptography ` +
          `registry entry. Category: ${site.spec.category}. Issue: ${site.spec.issue}`,
        rationale:
          `Cryptographic primitives shipped by this library cannot satisfy modern security ` +
          `requirements. ${site.spec.issue} A consumer who uses the library's primary API inherits ` +
          `the weakness; even a consumer who currently uses only its safe APIs is a future-proof ` +
          `liability — the next contributor will reach for the first primitive the library exports.`,
      })
      .sink({
        sink_type: "credential-exposure",
        location: site.dependencyLocation,
        observed:
          `${site.name} cryptographic operations fall within the scope of ${site.spec.category}. ` +
          `Hashed credentials may be recovered, encrypted data decrypted, signatures forged.`,
        cve_precedent: site.spec.cve,
      })
      .mitigation({
        mitigation_type: "input-validation",
        present: false,
        location: site.configLocation,
        detail:
          site.spec.safe_min_version === null
            ? `No safe version exists — replacement (${site.spec.replacement}) is the only fix.`
            : `Current version ${site.version} is below safe minimum ${site.spec.safe_min_version}. ` +
              `Upgrade path: ${site.spec.replacement}.`,
      })
      .impact({
        impact_type: "credential-theft",
        scope: "user-data",
        exploitability: "moderate",
        scenario:
          `Data protected by ${site.name} — hashed passwords, encrypted tokens, JWT-signed session ` +
          `state — can be recovered, decrypted, or forged using published attacks against ` +
          `${site.spec.category}. The MCP server's trust boundary with connected services collapses.`,
      })
      .factor(
        "weak_crypto_package_hit",
        0.18,
        `${site.name}@${site.version} is a confirmed weak-cryptography dependency (category: ` +
          `${site.spec.category}).`,
      );

    if (site.firedBySemverGate && site.spec.safe_min_version) {
      builder.factor(
        "below_safe_semver_floor",
        0.06,
        `Installed version ${site.version} is strictly below safe minimum ${site.spec.safe_min_version}.`,
      );
    }

    builder.reference(REF_CWE_327);
    builder.verification(stepCheckInstalledVersion(site));
    builder.verification(stepConsultCwe327(site));
    builder.verification(stepInspectManifest(site));

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

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `D6 charter caps confidence at ${cap}. Head-room reserved for the caller who imports the ` +
      `library but calls only its safe APIs, and for rare compatibility needs with legacy systems.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new WeakCryptographyDependenciesRule());

export { WeakCryptographyDependenciesRule };
