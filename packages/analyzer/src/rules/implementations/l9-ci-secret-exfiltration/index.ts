/**
 * L9 — CI/CD Secret Exfiltration Patterns, Rule Standard v2.
 *
 * REPLACES the L9 definition in
 * `packages/analyzer/src/rules/implementations/secret-exfil-detector.ts`.
 *
 * Detection is a structural AST scan (see gather.ts). For every exfil
 * sink call (fetch / dns.resolve / console.log / fs.writeFile / etc.)
 * whose argument subtree references a secret-named env read OR a bulk
 * env dump, L9 emits a v2 RuleResult with:
 *
 *   - source link (source_type "environment")
 *   - propagation link per AST hop (alias / template / wrapper / spread)
 *   - sink link (network-send / credential-exposure / file-write per channel)
 *   - mitigation link (present when a charter-audited masking call was
 *     observed in the enclosing function scope)
 *   - impact link (credential-theft → connected-services)
 *   - threat reference CVE-2025-30066 (+ Shai-Hulud + Datadog paper refs
 *     live in CHARTER.md)
 *
 * Zero regex literals. Zero string arrays > 5. All data in `./data/config.ts`.
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
  type SinkLink,
  type ImpactLink,
} from "../../../evidence.js";
import { gatherL9, type ExfilFact } from "./gather.js";
import {
  stepInspectEnvSource,
  stepInspectExfilSink,
  stepTracePropagation,
  stepInspectMitigation,
  stepCheckCiSecretMasking,
} from "./verification.js";

const RULE_ID = "L9";
const RULE_NAME = "CI/CD Secret Exfiltration Patterns";
const OWASP = "MCP07-insecure-config" as const;
const MITRE = "AML.T0057" as const;
const CONFIDENCE_CAP = 0.88;

const REMEDIATION =
  "Never transmit CI environment variables containing secrets. Audit every " +
  "fetch/axios/dns call and every console.log/logger.info in build, publish, " +
  "and install scripts. Use GitHub Actions `::add-mask::` or `core.setSecret()` " +
  "to prevent log exposure — note that masking only covers logs, not network " +
  "exfil. Replace long-lived PATs / NPM tokens with short-lived OIDC tokens " +
  "(GitHub Actions `permissions: id-token: write`, npm `--provenance`). " +
  "Restrict secret access to specific jobs via `environment:` scoping. If the " +
  "exfil path dumps the full environment (JSON.stringify(process.env)), " +
  "remove the dump entirely — there is no safe subset.";

const SUPPRESSED_REMEDIATION =
  "A charter-audited masking primitive was detected in the enclosing scope. " +
  "If that call truly resolves to the CI runtime's secret-masking API, log " +
  "exposure is neutralised but network / file-write exfil remains in scope " +
  "(masking only covers stdout / stderr channels).";

function sinkTypeForChannel(channel: ExfilFact["sink"]["channel"]): SinkLink["sink_type"] {
  switch (channel) {
    case "network":
    case "dns":
      return "network-send";
    case "log":
      return "credential-exposure";
    case "artifact":
      return "file-write";
  }
}

function impactTypeForChannel(_channel: ExfilFact["sink"]["channel"]): ImpactLink["impact_type"] {
  // All L9 channels end in the same user-visible impact: credential theft.
  return "credential-theft";
}

function impactScenario(fact: ExfilFact): string {
  const provider =
    fact.secret.markers.find((m) => m.kind === "provider")?.example ??
    fact.secret.markers[0]?.example ??
    "a CI-injected secret";
  const bulk = fact.secret.bulk
    ? ` Bulk-dump variant: the WHOLE environment (every injected secret at once) is captured.`
    : "";
  return (
    `CI secret ${fact.secret.envName} (class: ${provider}) is read from the environment and flows ` +
    `${fact.propagation.length} hop(s) to \`${fact.sink.name}\` (${fact.sink.channel}). ` +
    `The attacker — whether a compromised dependency running during postinstall, a malicious GitHub ` +
    `Action, or an injected step — receives the credential and gains access to the victim's registry / ` +
    `cloud / repository. CVE-2025-30066 (tj-actions/changed-files) and the Shai-Hulud worm (Sept 2025) ` +
    `both demonstrated this attack class at ecosystem scale; the median time from exfil to credential ` +
    `abuse was 7 minutes (Datadog DevSecOps 2026).${bulk}`
  );
}

function sourceRationale(fact: ExfilFact): string {
  const markers = fact.secret.bulk
    ? `bulk-env-dump (${fact.secret.bulkShape?.description})`
    : fact.secret.markers.map((m) => m.token).join(", ");
  return (
    `Environment read classified as a CI secret — matched markers: ${markers}. In CI/CD ` +
    `environments, such variables carry registry tokens (npm publish, GitHub PAT), cloud ` +
    `credentials (AWS / GCP / Azure), or service API keys. An env read on the path to an ` +
    `attacker-reachable ${fact.sink.channel} sink IS a credential-theft primitive.`
  );
}

export class CISecretExfiltrationRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherL9(context);
    if (gathered.mode !== "facts") return [];

    const out: RuleResult[] = [];
    for (const fact of gathered.facts) {
      out.push(this.buildFinding(fact));
    }
    return out;
  }

  private buildFinding(fact: ExfilFact): RuleResult {
    const sanitiserSuppresses = fact.mitigation !== null;
    const severity = sanitiserSuppresses ? "informational" : fact.sink.severity;

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "environment",
        location: fact.secret.location,
        observed: fact.secret.observed,
        rationale: sourceRationale(fact),
      });

    for (const hop of fact.propagation) {
      builder.propagation({
        propagation_type:
          hop.kind === "alias-binding"
            ? "variable-assignment"
            : hop.kind === "template-embed"
              ? "template-literal"
              : hop.kind === "wrapper-call"
                ? "function-call"
                : "direct-pass",
        location: hop.location,
        observed: hop.observed,
      });
    }

    builder
      .sink({
        sink_type: sinkTypeForChannel(fact.sink.channel),
        location: fact.sinkLocation,
        observed: `${fact.sink.name}: ${fact.sinkObserved.slice(0, 80)}`,
        cve_precedent: "CVE-2025-30066",
      })
      .mitigation({
        mitigation_type: "sanitizer-function",
        present: sanitiserSuppresses,
        location: fact.mitigationLocation ?? fact.sinkLocation,
        detail: sanitiserSuppresses
          ? `Charter-audited masking primitive \`${fact.mitigation?.name}\` observed in the enclosing function scope — ${fact.mitigation?.description}.`
          : "No charter-audited masking primitive (addMask / core.setSecret / maskSecret / " +
            "redactSecret) observed in the enclosing function scope. The secret flows unmasked " +
            "to the exfil sink.",
      })
      .impact({
        impact_type: impactTypeForChannel(fact.sink.channel),
        scope: "connected-services",
        exploitability: fact.propagation.length === 0 ? "trivial" : "moderate",
        scenario: impactScenario(fact),
      })
      .factor(
        "secret_name_heuristic",
        fact.secret.bulk ? 0.12 : 0.1,
        fact.secret.bulk
          ? `Bulk env dump: ${fact.secret.bulkShape?.description}. The whole environment flows ` +
            `through the sink — every CI-injected secret is exposed simultaneously.`
          : `Secret-name markers matched on env read \`${fact.secret.envName}\`: ` +
            `${fact.secret.markers.map((m) => m.token).join(", ")}. At least one is a ` +
            `credential-class or provider-specific CI secret name.`,
      )
      .factor(
        "unmitigated_sink_reachability",
        sanitiserSuppresses ? -0.2 : 0.08,
        sanitiserSuppresses
          ? `Charter-audited masking primitive \`${fact.mitigation?.name}\` observed — sink is ` +
            "partially neutralised (log channel only; network / file-write variants still reach the sink)."
          : `No masking primitive in the enclosing scope — the env read flows unmasked to a ` +
            `${fact.sink.channel} sink that crosses the CI trust boundary. Sink reachability is ` +
            `trivial: a reviewer can paste the verbatim sink expression into a curl / node -e ` +
            `command and reproduce the exfil.`,
      )
      .factor(
        "sink_channel_classification",
        0,
        `Sink channel: ${fact.sink.channel} (${fact.sink.rationale}).`,
      )
      .factor(
        "propagation_hops",
        fact.propagation.length === 0 ? 0.05 : fact.propagation.length >= 3 ? -0.05 : 0.02,
        fact.propagation.length === 0
          ? "Direct source→sink — secret reference appears verbatim inside the sink call argument."
          : `${fact.propagation.length} propagation hop(s) — each is independently verifiable ` +
            `in the chain above.`,
      )
      .reference({
        id: "CVE-2025-30066",
        title: "tj-actions/changed-files — CI secret exfiltration via workflow logs",
        url: "https://nvd.nist.gov/vuln/detail/CVE-2025-30066",
        year: 2025,
        relevance:
          "Canonical L9 precedent — a compromised GitHub Action read secrets from process.env and " +
          "exposed them in workflow logs. Every CI pipeline that prints or transmits `*_TOKEN` / " +
          "`*_SECRET` / `*_API_KEY` env vars is exploitable by the same primitive.",
      })
      .verification(stepInspectEnvSource(fact.secret))
      .verification(stepInspectExfilSink(fact))
      .verification(stepTracePropagation(fact));
    const mitigationStep = stepInspectMitigation(fact);
    if (mitigationStep) builder.verification(mitigationStep);
    builder.verification(stepCheckCiSecretMasking());

    const chain = builder.build();
    capConfidence(chain, CONFIDENCE_CAP);

    return {
      rule_id: RULE_ID,
      severity,
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: sanitiserSuppresses ? SUPPRESSED_REMEDIATION : REMEDIATION,
      chain,
    };
  }
}

function capConfidence(chain: EvidenceChain, cap: number): void {
  if (chain.confidence <= cap) return;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `L9 charter caps confidence at ${cap} — CI-level secret masking (::add-mask::), OIDC ` +
      `token scope, and environment-level masking are not observable at source-file scope, so ` +
      `a maximum-confidence claim would overstate the static evidence.`,
  });
  chain.confidence = cap;
}

registerTypedRuleV2(new CISecretExfiltrationRule());
