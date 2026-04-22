/**
 * K10 — Package Registry Substitution (Rule Standard v2).
 *
 * Orchestrator. Consumes K10Fact[] from gather.ts; emits one RuleResult
 * per untrusted registry URL. Enterprise-mirror URLs do NOT fire a
 * high-severity finding — they produce an informational advisory so
 * legitimate Artifactory / Nexus / Verdaccio deployments are not
 * drowned in false-positive noise.
 *
 * Zero regex. Confidence cap 0.80 per CHARTER §"Why confidence is
 * capped at 0.80".
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
import { gatherK10, type K10Classification, type K10Fact } from "./gather.js";
import {
  stepCheckIntegrity,
  stepCheckScopePrecedence,
  stepInspectRegistryUrl,
} from "./verification.js";

const RULE_ID = "K10";
const RULE_NAME = "Package Registry Substitution";
const OWASP = "MCP10-supply-chain" as const;
const MITRE = "AML.T0017" as const;
const CONFIDENCE_CAP = 0.8;

const REMEDIATION =
  "Use only trusted package registries for production resolution: " +
  "registry.npmjs.org, pypi.org, proxy.golang.org, registry.yarnpkg.com, " +
  "files.pythonhosted.org. If an enterprise mirror is required (Artifactory, " +
  "Nexus, Verdaccio, JFrog), (1) scope the registry to a specific package " +
  "namespace via `@scope:registry=…` so global resolution still flows " +
  "through the official registry, (2) require HTTPS — never plain HTTP, " +
  "(3) commit a lockfile that pins integrity hashes (package-lock.json " +
  "integrity fields, go.sum, yarn.lock integrity, or pip's " +
  "--require-hashes), (4) verify the mirror's upstream proxy is the " +
  "official registry. Required by ISO 27001 A.5.21 (supply-chain " +
  "information-security management) and OWASP ASI04 (Agentic Supply " +
  "Chain Vulnerabilities).";

class PackageRegistrySubstitutionRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherK10(context);
    if (gathered.isTestFile) return [];
    const out: RuleResult[] = [];
    for (const fact of gathered.facts) {
      if (fact.classification === "trusted") continue; // no finding
      out.push(this.buildFinding(fact));
    }
    return out;
  }

  private buildFinding(fact: K10Fact): RuleResult {
    const isEnterprise = fact.classification === "enterprise-mirror";

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: fact.location,
        observed: fact.observed,
        rationale: classificationRationale(fact.classification, fact),
      })
      .propagation({
        propagation_type: "function-call",
        location: fact.location,
        observed:
          `${fact.ecosystem} package manager resolves every dependency through ` +
          `${fact.url}${fact.scoped ? " (scoped)" : " (global)"}.`,
      })
      .sink({
        sink_type: "code-evaluation",
        location: fact.location,
        observed:
          `Every package downloaded from ${fact.url} executes during install ` +
          `(postinstall hooks) and at runtime (import / require).`,
      })
      .mitigation({
        mitigation_type: "input-validation",
        present: fact.integrityHashPresent,
        location: fact.location,
        detail: fact.integrityHashPresent
          ? `Integrity hashes are configured (${fact.ecosystem} lockfile present). ` +
            `This mitigates post-pin version swap; it does NOT validate the ` +
            `FIRST resolution from the registry.`
          : `No integrity-hash mechanism observed. Every resolution trusts the ` +
            `registry unconditionally.`,
      })
      .impact({
        impact_type: "remote-code-execution",
        scope: "connected-services",
        exploitability: isEnterprise ? "moderate" : "trivial",
        scenario: isEnterprise
          ? `The URL looks like an enterprise mirror (Artifactory / Nexus / ` +
            `Verdaccio / JFrog / localhost / private.<corp>). A reviewer must ` +
            `verify (a) the mirror is under the organisation's control, ` +
            `(b) it proxies from the official registry, and (c) integrity ` +
            `hashes are pinned. If any of the three is false, the mirror ` +
            `becomes the substitution primitive's delivery point.`
          : `The URL is not a known trusted or enterprise-shaped host. Every ` +
            `package the MCP server depends on is resolved through this URL, ` +
            `including transitive dependencies. An attacker controlling the ` +
            `URL serves modified versions of any package — the exact ` +
            `primitive Alex Birsan demonstrated against Apple, Microsoft, ` +
            `PayPal, Shopify, and Netflix in February 2021.` +
            (fact.httpsOnly
              ? ""
              : ` The URL also uses plain HTTP: even if the hostname is ` +
                `benign, an on-path attacker can inject content without any ` +
                `certificate bypass required.`),
      })
      .factor(
        "registry_url_classified",
        isEnterprise ? 0.05 : 0.12,
        `Classification: ${fact.classification}. ${
          isEnterprise
            ? "Enterprise-mirror substring match lowers (but does not eliminate) the finding's severity."
            : "URL does not match any trusted host or enterprise-shaped mirror substring."
        }`,
      )
      .factor(
        "trust_comparison",
        0.08,
        `Trusted ${fact.ecosystem} registry for comparison: ${trustedRegistryFor(fact.ecosystem)} — this URL replaces it.`,
      )
      .factor(
        fact.integrityHashPresent ? "integrity_hash_present" : "integrity_hash_mitigation_absent",
        fact.integrityHashPresent ? -0.08 : 0.06,
        fact.integrityHashPresent
          ? `Integrity hashes mitigate post-pin swap; first resolution is still unchecked.`
          : `No integrity enforcement — resolution trusts the registry unconditionally.`,
      )
      .factor(
        fact.httpsOnly ? "https_transport" : "http_transport_amplifier",
        fact.httpsOnly ? 0 : 0.08,
        fact.httpsOnly
          ? `HTTPS transport is enforced at least for this URL.`
          : `Plain HTTP transport — on-path attackers can inject content.`,
      )
      .factor(
        fact.scoped ? "scope_limiter_present" : "global_registry",
        fact.scoped ? -0.05 : 0.03,
        fact.scoped
          ? `URL is scope-limited to a specific package namespace; global resolution is unaffected.`
          : `URL is global; every package resolution passes through it.`,
      )
      .reference({
        id: "Birsan-Dependency-Confusion-2021",
        title:
          "Alex Birsan: Dependency Confusion — How I Hacked Into Apple, " +
          "Microsoft and Dozens of Other Companies",
        url: "https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610",
        year: 2021,
        relevance:
          `Birsan's research is the primary ecosystem exemplar for the ` +
          `registry-substitution primitive; ISO 27001 A.5.21 and CWE-829 ` +
          `are the compliance framings.`,
      })
      .verification(stepInspectRegistryUrl(fact))
      .verification(stepCheckIntegrity(fact))
      .verification(stepCheckScopePrecedence(fact));

    const chain = capConfidence(builder.build(), CONFIDENCE_CAP);

    return {
      rule_id: RULE_ID,
      severity: isEnterprise ? "medium" : "high",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain,
    };
  }
}

function classificationRationale(kind: K10Classification, fact: K10Fact): string {
  switch (kind) {
    case "enterprise-mirror":
      return (
        `A ${fact.ecosystem} registry URL (${fact.url}) with an enterprise-` +
        `mirror substring (Artifactory / Nexus / Verdaccio / JFrog / ` +
        `localhost / private) is configured. The URL is not on the trusted ` +
        `public registry list; legitimate enterprise mirrors exist but each ` +
        `one must be individually verified to proxy the official registry ` +
        `upstream and enforce integrity pinning.`
      );
    case "untrusted-external":
      return (
        `A ${fact.ecosystem} registry URL (${fact.url}) is configured whose ` +
        `hostname does not match any trusted public registry and does not ` +
        `match any enterprise-shaped substring. Every package resolution ` +
        `flows through this host; a compromised host becomes every install's ` +
        `RCE primitive (Birsan 2021). ${
          fact.httpsOnly ? "" : "The URL also uses plain HTTP — no transport-level defence."
        }`
      );
    case "trusted":
      return `Trusted registry URL (${fact.url}) — no finding should fire here.`;
  }
}

function trustedRegistryFor(ecosystem: K10Fact["ecosystem"]): string {
  switch (ecosystem) {
    case "npm":
      return "https://registry.npmjs.org/";
    case "yarn":
      return "https://registry.yarnpkg.com/";
    case "pip":
      return "https://pypi.org/simple/";
    case "go":
      return "https://proxy.golang.org";
  }
}

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `K10 charter caps confidence at ${cap}. Enterprise-shaped mirrors are ` +
      `legitimate supply-chain tooling; the substring heuristic ` +
      `distinguishing enterprise from truly untrusted mirrors is imperfect. ` +
      `0.80 reserves confidence for reviewer judgement on edge cases.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new PackageRegistrySubstitutionRule());

export { PackageRegistrySubstitutionRule };
