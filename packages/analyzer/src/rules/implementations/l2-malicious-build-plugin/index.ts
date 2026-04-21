/**
 * L2 — Malicious Build Plugin Injection (Rule Standard v2).
 *
 * REPLACES the L2 (MaliciousBuildPluginRule) class in
 * `packages/analyzer/src/rules/implementations/advanced-supply-chain-detector.ts`.
 *
 * Detection is structural:
 *   1. JSON.parse package.json → inspect install-lifecycle hook bodies.
 *   2. TypeScript AST walk of rollup/vite/webpack/esbuild config files →
 *      find dangerous API calls inside bundler-hook function literals.
 *   3. TypeScript AST walk → flag dynamic-plugin-load and URL-import
 *      patterns that defeat lockfile integrity.
 *
 * No regex literals outside `data/`.
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
import { gatherL2, type L2Fact } from "./gather.js";
import {
  stepInspectOffendingSite,
  stepCheckLockfileIntegrity,
  stepInspectCIContext,
} from "./verification.js";

const RULE_ID = "L2";
const RULE_NAME = "Malicious Build Plugin Injection";
const OWASP = "MCP10-supply-chain" as const;
const MITRE = "AML.T0017" as const;
const CONFIDENCE_CAP = 0.85;

const REMEDIATION =
  "Audit every plugin in your bundler configuration BEFORE adding it to " +
  "the build. Pin plugin versions in the lockfile and enable lockfile " +
  "integrity checks (`npm ci`, `pnpm install --frozen-lockfile`, " +
  "`yarn install --immutable`). Upgrade Rollup to ≥ 4.59.0 to mitigate " +
  "CVE-2026-27606 path traversal. Run bundler steps in isolated CI " +
  "containers with no network egress except to the registry. Never " +
  "import plugins from HTTP(S) URLs; if a plugin is not publishable to " +
  "npm, vendor the source into the repository and review it on every " +
  "update. Do not compute plugin identity from environment variables or " +
  "runtime expressions — the build plugin set must be visible to static " +
  "review.";

class MaliciousBuildPluginRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherL2(context);
    if (gathered.mode !== "facts") return [];
    return gathered.facts.map((f) => this.buildFinding(f));
  }

  private buildFinding(fact: L2Fact): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type:
          fact.kind === "install-hook-dangerous" ? "external-content" : "file-content",
        location: fact.location,
        observed: fact.observed,
        rationale: this.sourceRationale(fact),
      })
      .sink({
        sink_type: this.sinkType(fact),
        location: fact.location,
        observed: fact.description,
        cve_precedent: "CVE-2026-27606",
      })
      .mitigation({
        mitigation_type: "sandbox",
        present: false,
        location: fact.location,
        detail:
          fact.kind === "install-hook-dangerous"
            ? "npm/pnpm/yarn run install hooks with the invoking user's full privileges. " +
              "`--ignore-scripts` is not the default and is routinely forgotten in CI."
            : "Bundler plugins execute inside the bundler's node process — no sandbox, " +
              "no capability model. `--ignore-scripts` does NOT apply to build-phase hooks.",
      })
      .impact({
        impact_type: "remote-code-execution",
        scope: "server-host",
        exploitability: fact.kind === "url-plugin-import" ? "trivial" : "moderate",
        scenario: this.impactScenario(fact),
      })
      .factor(
        "dangerous_hook_api_call",
        fact.kind === "plugin-hook-dangerous-api" ? 0.18 : 0,
        fact.kind === "plugin-hook-dangerous-api"
          ? `Plugin hook '${fact.hookName}' body invokes ${fact.api?.name} ` +
            `(family: ${fact.api?.family}). ${fact.api?.description}.`
          : "Not a plugin-hook finding; factor recorded at 0 for contract completeness.",
      )
      .factor(
        "install_time_fetch_primitive",
        fact.kind === "install-hook-dangerous" ? 0.15 : 0,
        fact.kind === "install-hook-dangerous"
          ? `Install hook '${fact.hookName}' contains a fetch-and-exec token, matching the ` +
            `ua-parser-js / event-stream / Shai-Hulud supply-chain-attack primitive.`
          : "Not an install-hook finding; factor recorded at 0 for contract completeness.",
      )
      .factor(
        "plugin_from_url_source",
        fact.kind === "url-plugin-import" ? 0.2 : fact.kind === "dynamic-plugin-load" ? 0.12 : 0,
        fact.kind === "url-plugin-import"
          ? "Plugin source is an HTTP(S) URL — no lockfile integrity, no registry review, " +
            "no supply-chain visibility."
          : fact.kind === "dynamic-plugin-load"
            ? "Plugin identity resolved at runtime from a non-literal argument. Static review " +
              "cannot prove which module loads — the strongest defeat of supply-chain audit."
            : "Not a URL/dynamic-load finding; factor recorded at 0 for contract completeness.",
      )
      .factor(
        "sensitive_env_read_adjacent",
        fact.readsSensitiveEnv ? 0.08 : 0,
        fact.readsSensitiveEnv
          ? "Flagged body references process.env or a known-sensitive env var " +
            "(NPM_TOKEN / GITHUB_TOKEN / ANTHROPIC_API_KEY / AWS_*). Combined with " +
            "the dangerous API, this matches the Shai-Hulud exfiltration pattern."
          : "No adjacent sensitive env read — may still exfil indirectly, factor at 0.",
      )
      .reference({
        id: "CVE-2026-27606",
        title: "Rollup build-plugin path traversal (arbitrary file write during bundling)",
        url: "https://nvd.nist.gov/vuln/detail/CVE-2026-27606",
        relevance:
          "Rollup <4.59.0 build plugins could write files outside the output directory " +
          "via the generateBundle hook's fileName control. The rule's detection of " +
          "`writeFileSync` / `writeFile` inside hook bodies is the static prerequisite " +
          "for exploitation.",
      })
      .verification(stepInspectOffendingSite(fact))
      .verification(stepCheckLockfileIntegrity(fact))
      .verification(stepInspectCIContext(fact));

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

  private sourceRationale(fact: L2Fact): string {
    switch (fact.kind) {
      case "install-hook-dangerous":
        return (
          "Install-lifecycle hooks execute during `npm install` / " +
          "`pnpm install` with the invoking user's full privileges. An " +
          "attacker who can land a dangerous hook in the published " +
          "manifest compromises every machine that installs the package."
        );
      case "plugin-hook-dangerous-api":
        return (
          "Bundler plugin hooks (generateBundle / transform / load / " +
          "resolveId / buildStart / buildEnd / writeBundle / onBuild / " +
          "setup) run INSIDE the bundler process with full node " +
          "privileges. A dangerous API call here executes during every " +
          "downstream build — there is no sandbox between the plugin " +
          "and the host OS."
        );
      case "dynamic-plugin-load":
        return (
          "require/import with a non-literal argument resolves at build " +
          "time to a module whose identity is not visible in a static " +
          "review. This is the canonical evasion technique against " +
          "lockfile-based supply-chain checks."
        );
      case "url-plugin-import":
        return (
          "Importing from an HTTP(S) URL places the plugin outside " +
          "the project's dependency graph. No lockfile entry, no " +
          "npm audit, no registry integrity — the plugin source can " +
          "change between every build."
        );
    }
  }

  private sinkType(fact: L2Fact): "command-execution" | "network-send" | "file-write" | "code-evaluation" {
    if (fact.kind === "install-hook-dangerous") return "command-execution";
    if (fact.kind === "url-plugin-import" || fact.kind === "dynamic-plugin-load") return "code-evaluation";
    switch (fact.api?.family) {
      case "command-execution":
        return "command-execution";
      case "network-fetch":
        return "network-send";
      case "file-write":
        return "file-write";
      default:
        return "code-evaluation";
    }
  }

  private impactScenario(fact: L2Fact): string {
    switch (fact.kind) {
      case "install-hook-dangerous":
        return (
          "Every developer / CI runner that installs this package runs " +
          "the flagged hook with the calling user's privileges. This is " +
          "the exact attack class that hit ua-parser-js (Oct 2021), " +
          "event-stream (Nov 2018), and chalk/debug (Sept 2025) — each " +
          "fetched a payload and executed it before any human review."
        );
      case "plugin-hook-dangerous-api":
        return (
          "The build process invokes the flagged hook. Dangerous API " +
          "execution inside the plugin:\n" +
          "- command-execution → shells out, reads secrets, modifies host files\n" +
          "- network-fetch → exfiltrates NPM_TOKEN / ANTHROPIC_API_KEY / AWS_* to attacker\n" +
          "- file-write → path traversal (CVE-2026-27606) writes to arbitrary locations\n" +
          "The output bundle is published to npm, propagating the compromise to all " +
          "downstream MCP server consumers."
        );
      case "dynamic-plugin-load":
        return (
          "The build loads an attacker-controlled module at bundle time. " +
          "The exact payload is unknown from static review; the " +
          "Shai-Hulud worm (Nov 2025) used this pattern to swap in a " +
          "worm plugin that re-published the infected package under the " +
          "maintainer's stolen token."
        );
      case "url-plugin-import":
        return (
          "Every bundle run fetches the plugin fresh from the URL. The " +
          "attacker (or a MITM) can substitute a malicious version at " +
          "any moment without producing any lockfile diff. Exfiltration, " +
          "output-bundle tampering, or persistence is trivially installed."
        );
    }
  }
}

function capChainConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `L2 charter caps confidence at ${cap}. Bundler plugins legitimately ` +
      `read and write files during a build; the rule cannot always prove ` +
      `the target file is OUTSIDE the configured output directory without ` +
      `full symbolic analysis.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new MaliciousBuildPluginRule());

export { MaliciousBuildPluginRule };
