/**
 * L6 — Config Directory Symlink Attack (Rule Standard v2).
 *
 * REPLACES the L6 (ConfigSymlinkRule) class in
 * `packages/analyzer/src/rules/implementations/advanced-supply-chain-detector.ts`.
 *
 * Structural, AST-based. Two orthogonal finding families:
 *   - symlink-creation → fs.symlink(target, linkPath) with target in
 *     the sensitive-paths vocabulary (write-side attack).
 *   - unguarded-read   → fs.readFile / fs.open / fs.createReadStream
 *     on a non-literal path with NO realpath/lstat/O_NOFOLLOW guard in
 *     scope (read-side attack, CVE-2025-53109/53110 class).
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
import { gatherL6, type L6Fact } from "./gather.js";
import {
  stepInspectCallSite,
  stepInspectMitigation,
  stepCheckBindMountBoundary,
} from "./verification.js";

const RULE_ID = "L6";
const RULE_NAME = "Config Directory Symlink Attack";
const OWASP = "MCP05-privilege-escalation" as const;
const MITRE = "AML.T0054" as const;
const CONFIDENCE_CAP = 0.85;

const REMEDIATION =
  "Always resolve user-controlled paths with fs.realpath() before the " +
  "root-containment check, AND verify the realpath result with " +
  "startsWith(rootDir). For POSIX-safe reads, open the file with " +
  "O_NOFOLLOW (fs.open(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW)) " +
  "so the kernel refuses to traverse a symlink. On Windows, use " +
  "fs.realpathSync.native() which honours junctions. Apply the " +
  "CVE-2025-53109 / CVE-2025-53110 patches for Anthropic's filesystem " +
  "MCP server. Never create a symlink whose target is a sensitive " +
  "system path (/etc/passwd, ~/.ssh, .claude/, .cursor/mcp.json). " +
  "When running inside a container, audit bind-mounts — a host-mounted " +
  "credential directory negates every in-container realpath check.";

class ConfigSymlinkAttackRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherL6(context);
    if (gathered.mode !== "facts") return [];
    return gathered.facts.map((f) => this.buildFinding(f));
  }

  private buildFinding(fact: L6Fact): RuleResult {
    const severity = this.pickSeverity(fact);

    const builder = new EvidenceChainBuilder()
      .source({
        source_type:
          fact.kind === "symlink-creation" ? "file-content" : "user-parameter",
        location: fact.location,
        observed: fact.observed.slice(0, 200),
        rationale: this.sourceRationale(fact),
      })
      .sink({
        sink_type: fact.kind === "symlink-creation" ? "file-write" : "file-write",
        location: fact.location,
        observed: `${fact.calleeName}(...) — ${this.sinkObservation(fact)}`,
        cve_precedent: "CVE-2025-53109",
      })
      .mitigation({
        mitigation_type: "input-validation",
        present: fact.guardPresent || fact.nofollowPresent,
        location: fact.location,
        detail: this.mitigationDetail(fact),
      })
      .impact({
        impact_type: "privilege-escalation",
        scope: "server-host",
        exploitability:
          fact.kind === "symlink-creation" && fact.linkPathInAttackerDir ? "trivial" : "moderate",
        scenario: this.impactScenario(fact),
      })
      .factor(
        "symlink-creation-to-sensitive-path",
        fact.kind === "symlink-creation" ? 0.18 : 0,
        fact.kind === "symlink-creation"
          ? `fs.${fact.calleeName}(...) creates a symlink whose target is ` +
            `"${fact.sensitiveTarget ?? "<unknown>"}", a known sensitive ` +
            `system path. Downstream privileged reads of the link follow ` +
            `through to the target.`
          : "Not a symlink-creation finding; factor recorded at 0 for contract completeness.",
      )
      .factor(
        "no-symlink-guard-before-read",
        fact.kind === "unguarded-read" && !fact.guardPresent ? 0.15 : 0,
        fact.kind === "unguarded-read"
          ? fact.guardPresent
            ? "A realpath-family guard was observed in scope. The finding is " +
              "still emitted because a guard that runs on a different path " +
              "than the read call does not close the TOCTOU race window."
            : "No realpath / realpathSync / lstat / lstatSync call observed " +
              "in the enclosing function — the read can follow any symlink " +
              "the attacker plants."
          : "Not an unguarded-read finding; factor recorded at 0 for contract completeness.",
      )
      .factor(
        "no-nofollow-on-open",
        fact.kind === "unguarded-read" && !fact.nofollowPresent ? 0.1 : 0,
        fact.kind === "unguarded-read"
          ? fact.nofollowPresent
            ? "O_NOFOLLOW / AT_SYMLINK_NOFOLLOW / RESOLVE_NO_SYMLINKS observed in scope — kernel-level protection in place."
            : "No kernel-level NOFOLLOW flag — the kernel WILL traverse symlinks if present."
          : "Not an unguarded-read finding; factor recorded at 0 for contract completeness.",
      )
      .factor(
        "link_path_in_attacker_config_dir",
        fact.linkPathInAttackerDir ? 0.1 : 0,
        fact.linkPathInAttackerDir
          ? "Symlink is created inside an attacker-reachable agent config directory " +
            "(.claude / .cursor / .gemini / .mcp.json / .vscode). Downstream agent " +
            "clients that read the config will follow through to the sensitive target."
          : "Link path is not inside a known agent config directory — impact is lower.",
      )
      .reference({
        id: "CVE-2025-53109",
        title: "Anthropic filesystem MCP server root boundary bypass via symlink",
        url: "https://nvd.nist.gov/vuln/detail/CVE-2025-53109",
        relevance:
          "Demonstrates real-world exploitation: startsWith-based root " +
          "containment without a realpath pre-check allowed a symlink " +
          "(inside the root) pointing to /etc/passwd to be read. L6 " +
          "detects the static prerequisite for this class of attack.",
      })
      .verification(stepInspectCallSite(fact))
      .verification(stepInspectMitigation(fact))
      .verification(stepCheckBindMountBoundary(fact));

    const chain = capChainConfidence(builder.build(), CONFIDENCE_CAP);
    return {
      rule_id: RULE_ID,
      severity,
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain,
    };
  }

  private pickSeverity(fact: L6Fact): "critical" | "high" {
    if (fact.kind === "symlink-creation") return "critical";
    // unguarded-read
    if (fact.guardPresent && fact.nofollowPresent) return "high";
    if (fact.guardPresent || fact.nofollowPresent) return "high";
    return "critical";
  }

  private sourceRationale(fact: L6Fact): string {
    return fact.kind === "symlink-creation"
      ? "Server code creates a symbolic link whose target is a sensitive " +
        "system path. Any subsequent read of the link by a privileged " +
        "process (MCP agent, CLI tool, filesystem indexer) follows through " +
        "to the sensitive target, bypassing the server's own boundary."
      : "Server code reads a filesystem path derived from user input without " +
        "symlink-aware containment. An attacker who can plant a symlink at " +
        "the resolved path (inside the sandbox root) uses the server as a " +
        "confused deputy to read files outside the root.";
  }

  private sinkObservation(fact: L6Fact): string {
    return fact.kind === "symlink-creation"
      ? `symlink writes \`${fact.sensitiveTarget ?? "<unknown>"}\` into the filesystem namespace`
      : `${fact.calleeName}(user-controlled-path) follows whatever the path resolves to`;
  }

  private mitigationDetail(fact: L6Fact): string {
    if (fact.kind === "symlink-creation") {
      return (
        "Symlink creation has no per-call mitigation — the act of placing " +
        "the link is the compromise. The only defence is not creating " +
        "symlinks whose targets are sensitive paths."
      );
    }
    if (fact.guardPresent && fact.nofollowPresent) {
      return (
        "Both a realpath-family guard and an O_NOFOLLOW-family flag were " +
        "observed in scope. A TOCTOU race between guard and read may still " +
        "exist if the operations use different file descriptors."
      );
    }
    if (fact.guardPresent) {
      return (
        "A realpath / lstat guard was observed in scope, but no O_NOFOLLOW " +
        "flag. The guard narrows the TOCTOU window; it does not eliminate it."
      );
    }
    if (fact.nofollowPresent) {
      return (
        "An O_NOFOLLOW / AT_SYMLINK_NOFOLLOW flag was observed in scope, " +
        "but no realpath resolution. The flag blocks direct symlink " +
        "traversal at open time, but relative-path containment bypasses " +
        "are still possible."
      );
    }
    return (
      "Neither a realpath-family guard nor a NOFOLLOW flag appears in " +
      "the enclosing function — the read is fully symlink-unaware."
    );
  }

  private impactScenario(fact: L6Fact): string {
    if (fact.kind === "symlink-creation") {
      return fact.linkPathInAttackerDir
        ? "Server writes a symbolic link inside an agent config directory " +
          "(.claude / .cursor / .gemini). The link's target is a sensitive " +
          "system file. When the downstream AI agent reads the config, it " +
          "reads the sensitive file, gaining access to credentials or auth " +
          "tokens. This is the poisoned-config class of attack seen in " +
          "the CVE-2025-53773 (GitHub Copilot cross-agent RCE) research."
        : "Server writes a symbolic link whose target is a sensitive system " +
          "path. Any privileged reader that follows the link reads the " +
          "sensitive target — credential theft, password file disclosure, " +
          "or PII exfiltration depending on the target.";
    }
    return (
      "Attacker replaces the target path with a symbolic link pointing at " +
      "a sensitive file (/etc/passwd, ~/.ssh/id_rsa, ~/.aws/credentials). " +
      "The server reads through the symlink, returning the sensitive " +
      "bytes to the caller. CVE-2025-53109 demonstrated this class live " +
      "against the Anthropic filesystem MCP server, where a startsWith() " +
      "containment check was bypassed with a symlink whose entry was " +
      "inside the declared root but whose target was /etc/passwd."
    );
  }
}

function capChainConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `L6 charter caps confidence at ${cap}. Node's fs APIs differ in ` +
      `their default symlink-following behaviour and the rule cannot ` +
      `always prove that a helper abstraction (e.g. a local safeOpen() ` +
      `wrapper) does or does not enforce O_NOFOLLOW.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new ConfigSymlinkAttackRule());

export { ConfigSymlinkAttackRule };
