/**
 * C5 — Hardcoded Secrets in Source Code (v2).
 *
 * REPLACES the C5 definition in
 * `packages/analyzer/src/rules/implementations/code-security-deep-detector.ts`.
 *
 * Zero regex literals. Zero string arrays > 5. All detection data lives
 * in `./data/secret-formats.ts` (under the guard-skipped `data/` dir).
 * Detection uses:
 *
 *   - TypeScript AST walk over every StringLiteral /
 *     NoSubstitutionTemplateLiteral (via gather.ts);
 *   - typed format specs (prefix + charset + length window) instead of
 *     regex — `String.prototype.startsWith` and an ADT charset validator;
 *   - Shannon entropy (packages/analyzer/src/rules/analyzers/entropy.ts);
 *   - structural test-file guard (runner import + top-level describe/it);
 *   - placeholder-marker + example-file filename guards.
 *
 * Confidence is capped at 0.85 per CHARTER — entropy signals are
 * probabilistic, placeholder detection is heuristic, and some
 * cryptographic constants legitimately look like credentials.
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import {
  EvidenceChainBuilder,
  type EvidenceChain,
} from "../../../evidence.js";
import { gatherC5, type SecretHit } from "./gather.js";
import {
  stepInspectCredentialPosition,
  stepCheckEnvironmentFallback,
  stepVerifyNotPlaceholder,
} from "./verification.js";

const RULE_ID = "C5";
const RULE_NAME = "Hardcoded Secrets (Entropy + Structural)";
const OWASP = "MCP07-insecure-config" as const;
const MITRE: string | null = null;
const CONFIDENCE_CAP = 0.85;

const REMEDIATION =
  "Move the credential out of source. Use environment variables " +
  "(process.env / os.environ) loaded from a .env file that is " +
  ".gitignore-d, or a managed secrets store (AWS Secrets Manager, " +
  "HashiCorp Vault, Doppler, 1Password Secrets Automation). After " +
  "removing the literal, ROTATE the credential — treat the value as " +
  "compromised because repository history preserves it even after the " +
  "literal is deleted from HEAD. Add a pre-commit hook (gitleaks / " +
  "trufflehog) to prevent future leaks.";

const REMEDIATION_WITH_ENV =
  "The file contains BOTH a hardcoded literal AND a process.env / " +
  "os.environ read. Remove the literal fallback — the env read is " +
  "already in place. Rotate the credential because the historical " +
  "commit still contains it. Add a pre-commit hook to prevent the " +
  "fallback pattern from reappearing.";

class HardcodedSecretsRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "entropy";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherC5(context);
    const out: RuleResult[] = [];
    for (const { file, hits } of gathered.perFile) {
      for (const hit of hits) {
        const finding = this.maybeBuildFinding(hit, file);
        if (finding) out.push(finding);
      }
    }
    return out;
  }

  private maybeBuildFinding(hit: SecretHit, file: string): RuleResult | null {
    // Suppression rules — the structural guards do NOT produce a finding.
    if (hit.isTestFile) return null;
    if (hit.placeholderNearby && hit.kind !== "pem-private-key") return null;
    if (hit.isExampleFile && hit.kind !== "pem-private-key") return null;
    // Entropy floor — generic identifier hits below 3.5 bits/char are
    // low-signal; the CHARTER keeps them silent.
    if (hit.kind === "generic-identifier" && hit.entropy < 3.5) return null;

    const severity = deriveSeverity(hit);
    const chain = this.buildChain(hit, file, severity);
    return {
      rule_id: RULE_ID,
      severity,
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: hit.hasEnvironmentLookup ? REMEDIATION_WITH_ENV : REMEDIATION,
      chain,
    };
  }

  private buildChain(
    hit: SecretHit,
    file: string,
    severity: "critical" | "high" | "medium",
  ): EvidenceChain {
    const issuer =
      hit.spec?.issuer ??
      (hit.kind === "pem-private-key"
        ? "PEM private key"
        : `credential-shaped assignment (${hit.identifierName ?? "unknown"})`);

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: hit.location,
        observed: hit.masked,
        rationale:
          `A string literal matching the ${issuer} format is hardcoded in this ` +
          `source file. Shannon entropy of the value is ${hit.entropy.toFixed(2)} ` +
          `bits/char — ${hit.entropy >= 4.5 ? "well above" : "above"} the ` +
          `3.5 bits/char floor used to filter identifiers and trivial passwords.`,
      })
      .sink({
        sink_type: "credential-exposure",
        location: hit.location,
        observed:
          `Committed credential literal "${hit.masked}" on line ${lineOf(hit)}.` +
          (hit.observedLine ? ` Line: \`${hit.observedLine.slice(0, 160)}\`` : ""),
      })
      .mitigation({
        mitigation_type: "input-validation",
        present: hit.hasEnvironmentLookup,
        location: hit.location,
        detail: hit.hasEnvironmentLookup
          ? `The file reads process.env / os.environ — a runtime override for the ` +
            `credential exists, but the committed literal is still leaked in the repo.`
          : `No process.env / os.environ read in this module — the literal is the ` +
            `ONLY source of the credential at runtime.`,
      })
      .impact({
        impact_type: "credential-theft",
        scope: "connected-services",
        exploitability: "trivial",
        scenario:
          `${issuer} credential "${hit.masked}" is visible to every reader of this ` +
          `repository (including forks and CI artefacts) and to every future git ` +
          `history viewer even after deletion. An attacker authenticates to the ` +
          `issuer with this credential and takes the actions the MCP server was ` +
          `designed to perform (cloud-API calls, SaaS operations, private-repo ` +
          `access, billing endpoints). Credential theft exploitability is ` +
          `trivial — no parsing required.`,
      });

    // Factor: token-format match (present iff a prefix spec matched).
    if (hit.spec !== null) {
      builder.factor(
        "token_format_match",
        hit.spec.precedenceTier === "highest" ? 0.2 : 0.1,
        `${hit.spec.issuer} ${hit.spec.id} format — prefix "${hit.spec.prefix}", ` +
          `charset ${hit.spec.charset}, suffix length window [${hit.spec.minSuffix}, ${hit.spec.maxSuffix}]. ` +
          `Precedence tier: ${hit.spec.precedenceTier}.`,
      );
    } else if (hit.kind === "pem-private-key") {
      builder.factor(
        "token_format_match",
        0.2,
        "PEM private-key header matched — this is a hardcoded asymmetric key, not an opaque token.",
      );
    } else {
      builder.factor(
        "credential_identifier_match",
        0.02,
        `Generic credential-shaped assignment: identifier "${hit.identifierName}" ` +
          `paired with a high-entropy string literal. No known token prefix matched — ` +
          `the format is unknown but the identifier signals intent.`,
      );
    }

    // Factor: entropy score.
    const entropyAdj = hit.entropy >= 4.5 ? 0.1 : hit.entropy >= 3.5 ? 0.02 : -0.2;
    builder.factor(
      "entropy_score",
      entropyAdj,
      `Shannon entropy ${hit.entropy.toFixed(2)} bits/char — ` +
        (hit.entropy >= 4.5
          ? "well above the 4.5 boost threshold, consistent with a random opaque token."
          : hit.entropy >= 3.5
            ? "above the 3.5 floor, consistent with an alphanumeric credential."
            : "below the 3.5 floor — borderline for credential detection."),
    );

    // Factor: placeholder absence.
    builder.factor(
      "placeholder_marker_absent",
      hit.placeholderNearby ? -0.3 : 0.05,
      hit.placeholderNearby
        ? "A placeholder marker (REPLACE / xxxxx / example / your_*_here) was found " +
          "on the same line — the value may be documentation, not a secret."
        : "No placeholder marker found on the line or inside the value — this is " +
          "consistent with a real credential, not a template.",
    );

    // Factor: structural test-file guard.
    builder.factor(
      "structural_test_file_guard",
      hit.isTestFile ? -0.5 : 0.02,
      hit.isTestFile
        ? "The enclosing file imports a test runner and uses top-level describe/it/test — fixture context."
        : "The enclosing file does NOT structurally look like a test fixture; the literal is in production-path code.",
    );

    builder.reference({
      id: "CWE-798",
      title: "CWE-798 Use of Hard-coded Credentials",
      url: "https://cwe.mitre.org/data/definitions/798.html",
      relevance:
        "A credential embedded in source code is accessible to every reader of the " +
        "repository AND every historical commit. Exploitation is trivial: copy the " +
        "literal, authenticate to the issuer, take any action the credential " +
        "authorises.",
    });

    builder.verification(stepInspectCredentialPosition(hit));
    builder.verification(stepCheckEnvironmentFallback(hit, file));
    builder.verification(stepVerifyNotPlaceholder(hit));

    const chain = builder.build();
    capConfidence(chain, CONFIDENCE_CAP);
    // Keep severity note for caller — unused locally but documents intent.
    void severity;
    return chain;
  }
}

function lineOf(hit: SecretHit): number {
  return hit.location.kind === "source" ? hit.location.line : 0;
}

function deriveSeverity(hit: SecretHit): "critical" | "high" | "medium" {
  if (hit.kind === "pem-private-key") return "critical";
  if (hit.spec && hit.spec.precedenceTier === "highest") return "critical";
  if (hit.spec) return "high";
  // generic-identifier hits: depend on entropy
  if (hit.entropy >= 4.5) return "high";
  return "medium";
}

function capConfidence(chain: EvidenceChain, cap: number): void {
  if (chain.confidence <= cap) return;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `C5 charter caps confidence at ${cap}. The remaining gap to 1.0 is ` +
      `reserved for legitimate high-entropy cryptographic constants (SHA-256 ` +
      `hashes, binary fingerprints, pre-provisioned JWT test vectors) that ` +
      `structurally resemble credentials but are intentional.`,
  });
  chain.confidence = cap;
}

registerTypedRuleV2(new HardcodedSecretsRule());

export { HardcodedSecretsRule };
