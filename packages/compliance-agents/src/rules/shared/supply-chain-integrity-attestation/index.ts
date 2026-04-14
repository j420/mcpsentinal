/**
 * Rule: supply-chain-integrity-attestation
 *
 * Flags servers that ship without any cryptographic integrity
 * attestation in the install path AND have at least one dependency
 * with a known CVE. Structure-only: we never fetch the network; we
 * reason over context.dependencies and the presence of standard
 * attestation markers in source files.
 */

import type { AnalysisContext } from "@mcp-sentinel/analyzer";

import {
  ComplianceRule,
  type ComplianceRuleMetadata,
} from "../../base-rule.js";
import type {
  EvidenceBundle,
  EvidencePointer,
  JudgedTestResult,
  RawTestResult,
} from "../../../types.js";
import {
  INTEGRITY_MARKERS,
  makeBundle,
  sourceTokenHits,
  standardJudge,
} from "../../../rule-kit/index.js";

interface DepFinding {
  name: string;
  version: string | null;
  cve_ids: readonly string[];
  unpinned: boolean;
}

interface AttestationFacts {
  attestation_markers_found: string[];
  cve_tagged_deps: DepFinding[];
  unpinned_deps: DepFinding[];
  total_deps: number;
  integrity_attestation: boolean;
}

const METADATA: ComplianceRuleMetadata = {
  id: "shared-supply-chain-integrity-attestation",
  name: "Supply Chain Integrity Attestation",
  severity: "high",
  intent:
    "Every server MUST ship with a verifiable integrity attestation in the install path (lockfile, SLSA provenance, sigstore) and MUST NOT ship CVE-tagged dependencies without remediation.",
  applies_to: [
    { framework: "owasp_mcp", category: "MCP10 — Supply Chain", control: "MCP10" },
    { framework: "owasp_asi", category: "ASI04 — Agentic Supply Chain", control: "ASI04" },
    { framework: "cosai", category: "T6 — Software Supply Chain", control: "T6" },
    { framework: "cosai", category: "T11 — Package Provenance", control: "T11" },
    { framework: "maestro", category: "L4 — Deployment & Infrastructure", control: "L4" },
    { framework: "eu_ai_act", category: "Article 15 — Accuracy, Robustness, Cybersecurity", control: "Art.15" },
    { framework: "mitre_atlas", category: "AML.T0056 — ML Supply Chain Compromise", control: "AML.T0056" },
  ],
  threat_refs: [
    {
      id: "CVE-2024-3094",
      title: "xz-utils upstream backdoor",
      year: 2024,
      relevance: "Canonical example of a supply-chain compromise caught only because one user noticed a 500ms sshd delay — provenance would have prevented it.",
    },
    {
      id: "GHSA-EVENT-STREAM-2018",
      title: "event-stream malicious update",
      year: 2018,
      relevance: "npm trust transfer with zero signature verification; the entire install base was compromised overnight.",
    },
    {
      id: "OWASP-MCP10",
      title: "OWASP MCP Top 10 — Supply Chain",
      relevance: "Names the failure class this rule structurally prevents.",
    },
    {
      id: "SLSA-V1.0",
      title: "SLSA v1.0 framework",
      relevance: "Defines the Levels the rule's attestation markers align with.",
    },
    {
      id: "NIST-SP-800-204D",
      title: "NIST SP 800-204D — Software supply chain security",
      relevance: "Regulatory baseline referenced by EU AI Act Art.15 cybersecurity requirements.",
    },
  ],
  strategies: ["supply-chain-pivot", "config-drift", "trust-inversion"],
  remediation:
    "Commit a lockfile with integrity hashes (package-lock.json, pnpm-lock.yaml, poetry.lock, Cargo.lock). Adopt SLSA-Level-2 provenance or Sigstore cosign signing. Gate installs on an advisory scanner (osv-scanner, pip-audit) and remediate CVEs before release. Pin git dependencies to exact commit SHAs.",
};

class SupplyChainIntegrityAttestationRule extends ComplianceRule {
  readonly metadata = METADATA;

  gatherEvidence(context: AnalysisContext): EvidenceBundle {
    const markersFound = sourceTokenHits(context, INTEGRITY_MARKERS);
    const hasAttestation = markersFound.length > 0;

    const deps = context.dependencies ?? [];
    const cveTagged: DepFinding[] = [];
    const unpinned: DepFinding[] = [];

    for (const dep of deps) {
      const unpinnedFlag = this.looksUnpinned(dep.version);
      const cveIds = dep.cve_ids ?? [];
      if (dep.has_known_cve && cveIds.length > 0) {
        cveTagged.push({
          name: dep.name,
          version: dep.version,
          cve_ids: cveIds,
          unpinned: unpinnedFlag,
        });
      }
      if (unpinnedFlag) {
        unpinned.push({
          name: dep.name,
          version: dep.version,
          cve_ids: cveIds,
          unpinned: true,
        });
      }
    }

    const pointers: EvidencePointer[] = [];

    if (!hasAttestation) {
      pointers.push({
        kind: "source-file",
        label: "integrity_attestation",
        location: "source_files",
        observed: "no lockfile, no SLSA, no sigstore signatures detected",
      });
    }

    for (const dep of cveTagged) {
      pointers.push({
        kind: "dependency",
        label: "CVE-tagged dependency without remediation",
        location: `dep:${dep.name}@${dep.version}`,
        observed: `cve=${dep.cve_ids.join(",")}`,
      });
    }

    for (const dep of unpinned) {
      pointers.push({
        kind: "dependency",
        label: "unpinned dependency",
        location: `dep:${dep.name}@${dep.version}`,
        observed: "version string is a range, not a concrete pin",
      });
    }

    const deterministicViolation = !hasAttestation && cveTagged.length > 0;

    const facts: AttestationFacts = {
      attestation_markers_found: markersFound,
      cve_tagged_deps: cveTagged,
      unpinned_deps: unpinned,
      total_deps: deps.length,
      integrity_attestation: hasAttestation,
    };

    return makeBundle({
      rule_id: this.metadata.id,
      context,
      summary: deterministicViolation
        ? `No integrity attestation found AND ${cveTagged.length} CVE-tagged dependency(ies)`
        : `Integrity attestation=${hasAttestation}, CVE deps=${cveTagged.length}, unpinned=${unpinned.length}`,
      facts: facts as unknown as Record<string, unknown>,
      pointers,
      deterministic_violation: deterministicViolation,
    });
  }

  judge(bundle: EvidenceBundle, raw: RawTestResult): JudgedTestResult {
    const facts = bundle.facts as unknown as AttestationFacts;
    // Build the deterministic finding list: CVE-tagged dep names plus the
    // synthetic "integrity_attestation" anchor for the no-lockfile case.
    const deterministicNames: string[] = [];
    if (!facts.integrity_attestation) {
      deterministicNames.push("integrity_attestation");
    }
    for (const dep of facts.cve_tagged_deps ?? []) {
      deterministicNames.push(dep.name);
    }
    const result = standardJudge({
      raw,
      deterministic: deterministicNames,
      ruleId: this.metadata.id,
    });
    return {
      ...raw,
      judge_confirmed: result.confirmed,
      judge_rationale: result.rationale,
    };
  }

  /**
   * Heuristic: a version string "looks unpinned" if it does NOT parse as
   * a concrete digit-dot-digit tag. We stay away from regex entirely —
   * just structural character checks.
   */
  private looksUnpinned(version: string | null): boolean {
    if (!version) return true;
    // Classic semver range prefixes.
    const first = version.charAt(0);
    if (first === "^" || first === "~" || first === ">" || first === "<" || first === "*") {
      return true;
    }
    // Range operators embedded (e.g. ">=1.0 <2.0") — any space means range.
    if (version.includes(" ")) return true;
    // Git/branch refs without commit pin.
    if (version.includes("git+") && !version.includes("#")) return true;
    // Tag / dist-tag aliases.
    if (version === "latest" || version === "next" || version === "main") return true;
    return false;
  }
}

export const supplyChainIntegrityAttestationRule =
  new SupplyChainIntegrityAttestationRule();
