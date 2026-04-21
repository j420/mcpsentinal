/**
 * K9 — Dangerous Post-Install Hooks (Structural + Lightweight Taint), v2.
 *
 * Detection is structural-first:
 *   1. JSON.parse the source — if it's a package.json with scripts.*,
 *      scan each install-lifecycle hook string against a token registry.
 *   2. If the source is a setup.py / pyproject.toml with an install
 *      cmdclass override, run the lightweight taint analyser over it
 *      for command_execution / url_request sinks.
 *
 * No regex literals. Detection data lives in `./data/dangerous-tokens.ts`.
 * Evidence chains carry `config`-kind Locations for JSON hooks and
 * `source`-kind Locations for Python cmdclass findings.
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder } from "../../../evidence.js";
import { gatherK9, type K9Fact } from "./gather.js";
import {
  stepInspectHook,
  stepTraceDangerousFamily,
  stepReviewInstallTimePrivileges,
} from "./verification.js";
import { capConfidence } from "../_shared/taint-rule-kit/index.js";

const RULE_ID = "K9";
const RULE_NAME = "Dangerous Post-Install Hooks (Structural + Taint)";
const OWASP = "MCP10-supply-chain" as const;
const MITRE = "AML.T0054" as const;
const CONFIDENCE_CAP = 0.9;

const REMEDIATION =
  "Remove network requests, base64 decoders, shell invocations, and " +
  "subprocess calls from install-lifecycle hooks (npm postinstall / " +
  "preinstall / install, Python setup.py cmdclass, pyproject.toml " +
  "build hooks). Install hooks should only run compile-time steps that " +
  "are deterministic and offline: node-gyp / prebuild / tsc / esbuild / " +
  "cmake. If a binary download is genuinely needed, publish a dedicated " +
  "prebuilt package for each platform. Configure CI / dev environments " +
  "with `--ignore-scripts` so no package's postinstall runs by default; " +
  "audit hooks per-package before enabling them.";

export class DangerousPostInstallRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherK9(context);
    if (gathered.mode !== "facts") return [];

    const out: RuleResult[] = [];
    for (const fact of gathered.facts) {
      out.push(this.buildFinding(fact));
    }
    return out;
  }

  private buildFinding(fact: K9Fact): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "external-content",
        location: fact.location,
        observed: fact.hookSnippet,
        rationale:
          `The ${fact.hook} install hook is the attacker's injection point: ` +
          `it runs during \`npm install\` / \`pip install\` with the calling ` +
          `user's full privileges BEFORE any runtime scanner can observe the ` +
          `package. A dependency that includes a dangerous hook therefore IS ` +
          `the supply-chain compromise (no further propagation is needed).`,
      })
      .sink({
        sink_type: "command-execution",
        location: fact.location,
        observed: `${fact.family}: ${fact.matchedToken}`,
        cve_precedent: "CWE-829",
      })
      .mitigation({
        mitigation_type: "confirmation-gate",
        present: false,
        location: fact.location,
        detail:
          "Install hooks execute automatically during dependency resolution; " +
          "there is no user confirmation, sandbox, or runtime check between " +
          "the hook and the host operating system.",
      })
      .impact({
        impact_type: "remote-code-execution",
        scope: "server-host",
        exploitability: "trivial",
        scenario:
          `Every developer / CI runner that installs this package has its ` +
          `host directly compromised: the ${fact.family} pattern in ` +
          `${fact.hook} ${fact.description}. This is the exact attack class ` +
          `that hit ua-parser-js (Oct 2021), event-stream (Nov 2018), colors ` +
          `(March 2022), and PyTorch nightly (Dec 2022) — each fetched a ` +
          `payload during install and executed it before any human review.`,
      })
      .factor(
        "install_hook_location_identified",
        0.2,
        `Hook identified: ${fact.hook}. The finding's Location points at ` +
          `${fact.location.kind === "config" ? fact.location.json_pointer : "the cmdclass run() method"} so a ` +
          `reviewer can open the exact entry in package.json / setup.py. ` +
          `The structural parse produced a specific JSON pointer, the ` +
          `strongest non-taint evidence this rule can produce.`,
      )
      .factor(
        "dangerous_command_family",
        fact.family === "fetch-and-exec" || fact.family === "inline-base64" ? 0.25 : 0.15,
        `Family: ${fact.family}. Matched token: \`${fact.matchedToken.slice(0, 80)}\`. ` +
          `Fetch-and-exec and inline-base64 are the highest-priority ` +
          `families per CHARTER lethal edge case 5 (pipe-to-shell canonical ` +
          `pattern) and 6 (base64 decode in hook). Token match on a known ` +
          `supply-chain-attack primitive carries the strongest factor.`,
      )
      .factor(
        "severity_adjustment",
        fact.severity === "critical" ? 0 : -0.1,
        fact.severity === "critical"
          ? "Severity stays at critical — fetch-and-exec / inline-base64 / " +
            "shell-invocation / subprocess-call / eval-call families are all " +
            "critical by charter."
          : `Severity downgraded to ${fact.severity} per CHARTER edge case — ` +
            `file-write-only or project-local helper script is not ` +
            `classic supply-chain RCE.`,
      )
      .reference({
        id: "CWE-829",
        title: "Inclusion of Functionality from Untrusted Control Sphere",
        url: "https://cwe.mitre.org/data/definitions/829.html",
        relevance:
          "Install hooks that fetch or execute code turn every dependency " +
          "install into a supply-chain RCE vector — the attack class of " +
          "ua-parser-js / event-stream / colors / PyTorch nightly.",
      })
      .verification(stepInspectHook(fact))
      .verification(stepTraceDangerousFamily(fact))
      .verification(stepReviewInstallTimePrivileges(fact));

    const chain = builder.build();
    capConfidence(chain, CONFIDENCE_CAP, RULE_ID);

    return {
      rule_id: RULE_ID,
      severity: fact.severity,
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain,
    };
  }
}

registerTypedRuleV2(new DangerousPostInstallRule());
