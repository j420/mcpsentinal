/**
 * C9 — Excessive Filesystem Scope (v2).
 *
 * REPLACES the C9 definition in
 * `packages/analyzer/src/rules/implementations/code-remaining-detector.ts`.
 *
 * Pure structural AST detection. Zero regex literals. Detection logic
 * lives in `./gather.ts`; configuration tables live in `./data/config.ts`.
 *
 * Confidence cap: 0.90 — gap reserved for OS-level isolation (Docker
 * user-namespace remap, unshare, chroot, k8s securityContext) the
 * static analyser cannot observe.
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
import { gatherC9, type FsScopeFact, type C9LeakKind } from "./gather.js";
import {
  stepInspectRootCall,
  stepCheckClampHelper,
  stepCheckDeploymentSandbox,
} from "./verification.js";

const RULE_ID = "C9";
const RULE_NAME = "Excessive Filesystem Scope";
const OWASP = "MCP03-command-injection" as const;
const MITRE = "AML.T0054" as const;
const CONFIDENCE_CAP = 0.9;

const REMEDIATION =
  "Restrict every filesystem operation to a specific bounded directory. " +
  "Compute a base directory at startup (e.g. `const BASE_DIR = path.resolve(" +
  "process.env.MCP_DATA_DIR ?? './data')`) and clamp every user-controlled " +
  "path against it: `const resolved = path.resolve(BASE_DIR, userPath); " +
  "if (!resolved.startsWith(BASE_DIR + path.sep)) throw new Error('path " +
  "escape');`. Prefer a charter-audited helper (isSubpath, resolveWithin, " +
  "safeJoin, ensureInside, validatePath) over ad-hoc string manipulation. " +
  "If your MCP server exposes a `roots` capability per the 2025-06-18 spec, " +
  "declare every root explicitly — bare \"/\" / unset roots collapse to the " +
  "entire filesystem. As defence in depth, run the MCP server under a " +
  "dedicated OS user with read-only mounts, or inside a Docker container " +
  "with `--user`, `--read-only`, and `--cap-drop=ALL`.";

class ExcessiveFsScopeRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherC9(context);
    if (gathered.mode !== "facts") return [];
    const out: RuleResult[] = [];
    for (const fact of gathered.facts) {
      out.push(this.buildFinding(fact));
    }
    return out;
  }

  private buildFinding(fact: FsScopeFact): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: fact.location,
        observed: fact.observed,
        rationale:
          `${describeKindLong(fact.kind)} establishes filesystem scope at the ` +
          `root directory. The MCP host process can read every file it has ` +
          `permission to, and an AI agent driving this tool inherits the ` +
          `same scope on every request.`,
      })
      .sink({
        sink_type: "file-write",
        location: fact.location,
        observed:
          `Filesystem operation rooted at "/". The scope-establishing ` +
          `expression IS the dangerous operation — the agent gets root-` +
          `level reach by design.`,
        cve_precedent: "CWE-732",
      })
      .mitigation({
        mitigation_type: "input-validation",
        present: false,
        location: fact.location,
        detail:
          fact.clampHelperPresent
            ? `A charter-clamp helper appears in the source but the rule ` +
              `cannot prove it precedes this scope-establishing operation. ` +
              `A reviewer must verify the order.`
            : `No charter-clamp helper anywhere in the source. Every path ` +
              `the agent supplies will be honoured against the entire ` +
              `filesystem with no validation.`,
      })
      .impact({
        impact_type: "privilege-escalation",
        scope: "server-host",
        exploitability: "trivial",
        scenario:
          `A single tool call returns the names / contents of every file ` +
          `the host process can read: /etc/passwd, /etc/shadow (when the ` +
          `process runs as root), ~/.ssh/id_rsa, the MCP server's own ` +
          `.env file, AWS credentials at ~/.aws/credentials, GCP ADC at ` +
          `~/.config/gcloud/. For write-capable variants, the agent ` +
          `overwrites systemd unit files, adds an ~/.ssh/authorized_keys ` +
          `entry, or replaces a config file with an attacker-controlled ` +
          `version. Exploitation is one prompt away — the agent does not ` +
          `need to escape any sandbox because the sandbox does not exist.`,
      })
      .factor(
        "ast_root_pattern",
        kindAdjustment(fact.kind),
        `Root-scope shape: ${fact.kind}. ${describeKindLong(fact.kind)}.`,
      )
      .factor(
        "root_call_kind",
        fact.kind === "fs-list-root" || fact.kind === "python-walk-root" ? 0.05 : 0.02,
        fact.kind === "fs-list-root" || fact.kind === "python-walk-root"
          ? "Listing / walking is full reconnaissance — every directory name leaks at once."
          : "Read / write / chdir at root scope is single-target but unbounded.",
      )
      .factor(
        "structural_test_file_guard",
        0.02,
        "AST-shape check ruled out a vitest/jest/pytest test fixture.",
      )
      .reference({
        id: "CWE-732",
        title: "CWE-732 Incorrect Permission Assignment for Critical Resource",
        url: "https://cwe.mitre.org/data/definitions/732.html",
        relevance:
          "An MCP filesystem tool that operates from \"/\" as its base " +
          "directory grants the AI agent the same filesystem privileges as " +
          "the MCP host process — almost always far broader than the " +
          "single-tool scope intended. Matches CWE-732 directly.",
      })
      .verification(stepInspectRootCall(fact))
      .verification(stepCheckClampHelper(fact))
      .verification(stepCheckDeploymentSandbox(fact));

    const chain = builder.build();
    capConfidence(chain, CONFIDENCE_CAP);

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

function kindAdjustment(kind: C9LeakKind): number {
  switch (kind) {
    case "fs-list-root":
      return 0.15;
    case "python-walk-root":
      return 0.15;
    case "base-path-root":
      return 0.12;
    case "chdir-root":
      return 0.1;
    case "fs-read-root":
      return 0.1;
  }
}

function describeKindLong(kind: C9LeakKind): string {
  switch (kind) {
    case "fs-list-root":
      return "Filesystem listing / glob / walk call rooted at /";
    case "fs-read-root":
      return "Filesystem read / open call rooted at /";
    case "chdir-root":
      return "Working-directory change to /";
    case "base-path-root":
      return "Base / allowed-paths configuration assigned the value \"/\"";
    case "python-walk-root":
      return "Python os.walk(\"/\") / Path(\"/\").iterdir() / os.listdir(\"/\") call";
  }
}

function capConfidence(chain: EvidenceChain, cap: number): void {
  if (chain.confidence <= cap) return;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `C9 charter caps confidence at ${cap}. The remaining gap to 1.0 is ` +
      `reserved for OS-level isolation (Docker user-namespace remap, ` +
      `unshare, chroot, k8s securityContext) the static analyser cannot ` +
      `observe.`,
  });
  chain.confidence = cap;
}

registerTypedRuleV2(new ExcessiveFsScopeRule());

export { ExcessiveFsScopeRule };
