/**
 * K11 — Missing Server Integrity Verification (v2).
 *
 * Emits one finding per runtime-loader site with no integrity evidence on the
 * lexical ancestor chain. Zero regex; confidence cap 0.88. Charter and
 * edge-case strategy are specified in `CHARTER.md`.
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
import { gatherK11, type LoaderSite } from "./gather.js";
import { stepInspectLoader, stepInspectIntegrityScope } from "./verification.js";

const RULE_ID = "K11";
const RULE_NAME = "Missing Server Integrity Verification";
const OWASP = "MCP10-supply-chain" as const;
const MITRE = "AML.T0054" as const;
const CONFIDENCE_CAP = 0.88;

const REMEDIATION =
  "Every runtime-loaded MCP server / plugin / module must carry integrity " +
  "evidence that the analyzer can point to. Acceptable mitigations: (1) hash " +
  "the artefact at load time via crypto.createHash and compare with an " +
  "expected value committed to source, (2) verify a digital signature " +
  "against a pinned public key, (3) consult a committed integrity manifest " +
  "(integrity.json / checksums.txt / SRI). For shell-mediated patterns " +
  "(curl | bash), replace with a package manager invocation whose " +
  "lockfile carries integrity hashes. CoSAI MCP-T6/T11 and ISO 27001 " +
  "A.8.24 treat the absence of such evidence as a supply-chain control " +
  "gap — independent of whether the artefact is, at this moment, benign.";

const REF_COSAI_T6 = {
  id: "CoSAI-MCP-T6",
  title: "CoSAI MCP Security — T6 Supply Chain Integrity",
  url: "https://www.coalitionforsecureai.org/publications/mcp-threat-taxonomy",
  relevance:
    "CoSAI T6 requires integrity verification for every loaded MCP component. " +
    "A runtime loader without an accompanying hash / signature / SRI check " +
    "violates the control regardless of the artefact's current contents.",
} as const;

class K11MissingServerIntegrityVerificationRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "composite";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherK11(context);
    const findings: RuleResult[] = [];
    for (const file of gathered.perFile) {
      if (file.isTestFile) continue;
      for (const site of file.sites) {
        if (site.integrityMitigation.present) continue;
        findings.push(this.buildFinding(site));
      }
    }
    // Cap output: no server needs more than 10 K11 findings per scan.
    return findings.slice(0, 10);
  }

  private buildFinding(site: LoaderSite): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: site.location,
        observed: site.observed,
        rationale:
          `Runtime loader "${site.calleeLabel}" (classified as ` +
          `\`${site.kind}\`) introduces external code into the server ` +
          `process. The resolved specifier, package version, or fetched ` +
          `payload can change between audits — integrity evidence is the ` +
          `only static artefact an auditor can point to.`,
      })
      .sink({
        sink_type: "code-evaluation",
        location: site.location,
        observed:
          `Loader evaluates external code / module without a hash or ` +
          `signature verification on the ancestor chain.`,
      })
      .mitigation({
        mitigation_type: "input-validation",
        present: false,
        location: site.enclosingFunctionLocation ?? site.location,
        detail:
          `No integrity-verifying call (crypto.createHash, verifyIntegrity, ` +
          `sri.check), no integrity-bearing identifier (sha256, checksum, ` +
          `digest), and no integrity manifest filename literal ` +
          `(integrity.json, checksums.txt, sha256sum.txt) was observed on ` +
          `the lexical ancestor chain from the loader up to file scope.`,
      })
      .impact({
        impact_type: "remote-code-execution",
        scope: "server-host",
        exploitability: "moderate",
        scenario:
          `A supply-chain attacker who controls the source — via ` +
          `typosquat, hijacked registry account, MITM on HTTPS for a ` +
          `non-pinned dependency, or a malicious mirror — ships arbitrary ` +
          `code that the server loads on its next start. The code runs in ` +
          `the agent's trust zone: it sees tool parameters, environment ` +
          `variables, and downstream tool calls. Alex Birsan's 2021 ` +
          `dependency-confusion campaign demonstrated this is exploitable ` +
          `at scale.`,
      })
      .factor(
        `dynamic_loader_${site.kind.split("-").join("_")}`,
        kindWeight(site.kind),
        `Loader classified as \`${site.kind}\` — regulator-facing ` +
          `taxonomy of the supply-chain entry surface.`,
      )
      .factor(
        "no_integrity_in_scope",
        0.10,
        `Ancestor walk from the loader to file scope found no integrity ` +
          `evidence. The static engine cannot prove absence of a ` +
          `middleware-level verification layer; the charter caps ` +
          `confidence at ${CONFIDENCE_CAP} for that reason.`,
      );

    builder.reference(REF_COSAI_T6);
    builder.verification(stepInspectLoader(site));
    builder.verification(stepInspectIntegrityScope(site));

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

function kindWeight(kind: LoaderSite["kind"]): number {
  switch (kind) {
    case "shell-fetch-execute":
      return 0.15;
    case "runtime-install":
      return 0.13;
    case "dynamic-import":
      return 0.10;
    case "mcp-server-ctor":
      return 0.09;
    case "server-load-method":
      return 0.08;
    case "require-call":
      return 0.07;
  }
}

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `K11 charter caps confidence at ${cap} — integrity configuration may ` +
      `live outside the analyzed file (process args, mounted secrets, ` +
      `boot-time allowlists). A maximum-confidence claim would overstate ` +
      `what static analysis can prove.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new K11MissingServerIntegrityVerificationRule());

export { K11MissingServerIntegrityVerificationRule };
