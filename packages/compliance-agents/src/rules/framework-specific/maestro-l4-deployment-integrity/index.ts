/**
 * Rule: maestro-l4-deployment-integrity
 *
 * MAESTRO L4 union check: supply-chain integrity markers AND runtime
 * sandbox markers must both be present. Fully structural token scan.
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
  SANDBOX_MARKERS,
  makeBundle,
  sourceTokenHits,
  standardJudge,
} from "../../../rule-kit/index.js";

interface L4Failure {
  id:
    | "no-integrity-markers"
    | "no-sandbox-markers";
  description: string;
}

interface L4Facts {
  l4_failures: L4Failure[];
  l4_deployment_integrity: string;
  integrity_markers_found: string[];
  sandbox_markers_found: string[];
}

const METADATA: ComplianceRuleMetadata = {
  id: "maestro-l4-deployment-integrity",
  name: "MAESTRO L4 — Deployment & Infrastructure Integrity",
  severity: "high",
  intent:
    "An MCP server at MAESTRO layer L4 MUST carry both supply-chain integrity markers (lockfile/SLSA/sigstore) AND runtime sandbox markers (seccomp/apparmor/gvisor/runAsNonRoot).",
  applies_to: [
    {
      framework: "maestro",
      category: "L4 — Deployment & Infrastructure",
      control: "L4",
    },
  ],
  threat_refs: [
    {
      id: "MAESTRO-L4-Spec",
      title: "MAESTRO threat model — layer 4 Deployment & Infrastructure",
      relevance: "Direct framework reference for the union check this rule performs.",
    },
    {
      id: "SLSA-V1.0",
      title: "SLSA Supply-chain Levels for Software Artifacts v1.0",
      relevance: "Framework this rule scans for supply-chain evidence.",
    },
    {
      id: "CIS-Docker-Benchmark",
      title: "CIS Docker Benchmark — runtime hardening baseline",
      relevance: "Baseline for the runtime sandbox markers this rule scans for.",
    },
  ],
  strategies: ["supply-chain-pivot", "boundary-leak", "config-drift"],
  remediation:
    "Check in a lockfile, publish SLSA v1.0 provenance, sign release artifacts with cosign, AND add a seccomp profile, AppArmor, or gvisor to the runtime. Both axes are mandatory for L4.",
};

class MaestroL4DeploymentIntegrityRule extends ComplianceRule {
  readonly metadata = METADATA;

  gatherEvidence(context: AnalysisContext): EvidenceBundle {
    const integrityHits = sourceTokenHits(context, INTEGRITY_MARKERS);
    const sandboxHits = sourceTokenHits(context, SANDBOX_MARKERS);

    const failures: L4Failure[] = [];
    const pointers: EvidencePointer[] = [];

    if (integrityHits.length === 0) {
      failures.push({
        id: "no-integrity-markers",
        description:
          "No lockfile / SLSA / SBOM / sigstore markers in source — L4 supply-chain axis failed.",
      });
      pointers.push({
        kind: "source-file",
        label: "no-integrity-markers",
        location: "source_files",
      });
    }
    if (sandboxHits.length === 0) {
      failures.push({
        id: "no-sandbox-markers",
        description:
          "No seccomp/apparmor/gvisor/runAsNonRoot/readOnlyRootFilesystem markers — L4 runtime axis failed.",
      });
      pointers.push({
        kind: "source-file",
        label: "no-sandbox-markers",
        location: "source_files",
      });
    }

    const facts: L4Facts = {
      l4_failures: failures,
      l4_deployment_integrity: "l4_deployment_integrity",
      integrity_markers_found: integrityHits,
      sandbox_markers_found: sandboxHits,
    };

    return makeBundle({
      rule_id: this.metadata.id,
      context,
      summary:
        failures.length > 0
          ? `${failures.length} MAESTRO L4 axis failure(s) (integrity=${integrityHits.length}, sandbox=${sandboxHits.length})`
          : `MAESTRO L4 axes present (integrity=${integrityHits.length}, sandbox=${sandboxHits.length})`,
      facts: facts as unknown as Record<string, unknown>,
      pointers,
      deterministic_violation: failures.length > 0,
    });
  }

  judge(bundle: EvidenceBundle, raw: RawTestResult): JudgedTestResult {
    const facts = bundle.facts as unknown as L4Facts;
    const deterministicIds: string[] = (facts.l4_failures ?? []).map((f) => f.id);
    if (deterministicIds.length > 0) deterministicIds.push("l4_deployment_integrity");
    const result = standardJudge({
      raw,
      deterministic: deterministicIds,
      ruleId: this.metadata.id,
    });
    return {
      ...raw,
      judge_confirmed: result.confirmed,
      judge_rationale: result.rationale,
    };
  }
}

export const maestroL4DeploymentIntegrityRule =
  new MaestroL4DeploymentIntegrityRule();
