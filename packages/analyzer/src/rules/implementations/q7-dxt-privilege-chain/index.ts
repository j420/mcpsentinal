/**
 * Q7 — Desktop Extension Privilege Chain (Rule Standard v2).
 *
 * Three CVE-backed ingress detectors: autoApprove flag,
 * chrome/browser native messaging, ipcMain.handle. Confidence
 * cap 0.82; severity critical.
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
import { gatherQ7, type DxtPrivilegeSite } from "./gather.js";
import { stepInspectSite, stepCheckCveContext } from "./verification.js";

const RULE_ID = "Q7";
const RULE_NAME = "Desktop Extension Privilege Chain (DXT)";
const OWASP = "MCP05-privilege-escalation" as const;
const MITRE = "AML.T0054" as const;
const CONFIDENCE_CAP = 0.82;

const REMEDIATION =
  "Do not ship MCP servers whose manifest includes `autoApprove: true` " +
  "(or autoStart / trust / trusted). Each tool invocation must require " +
  "per-invocation user confirmation. Do not bridge browser-extension " +
  "native-messaging (`chrome.runtime.sendNativeMessage`) into the MCP " +
  "boundary without an explicit consent dialog. Gate every " +
  "`ipcMain.handle` handler behind a signed token or an explicit " +
  "user-gesture prompt. CVE-2025-54135 (Cursor CurXecute), " +
  "CVE-2025-54136 (MCPoison), and CVE-2025-59536 (Claude Code .mcp.json) " +
  "document the exact attack chain this rule detects.";

const STRATEGY_SHARED_VOCAB = "shared-dxt-sinks-vocabulary";
const STRATEGY_AUTO_APPROVE = "auto-approve-flag-match";
const STRATEGY_NATIVE_MSG = "native-messaging-bridge-match";
const STRATEGY_IPC = "ipc-handler-mcp-match";

class DxtPrivilegeChainRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  readonly edgeCaseStrategies = [
    STRATEGY_SHARED_VOCAB,
    STRATEGY_AUTO_APPROVE,
    STRATEGY_NATIVE_MSG,
    STRATEGY_IPC,
  ] as const;

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherQ7(context);
    return gathered.sites.map((s) => this.buildFinding(s)).slice(0, 10);
  }

  private buildFinding(site: DxtPrivilegeSite): RuleResult {
    const chain = this.buildChain(site);
    return {
      rule_id: RULE_ID,
      severity: "critical",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain,
    };
  }

  private buildChain(site: DxtPrivilegeSite): EvidenceChain {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: site.location,
        observed: site.observed,
        rationale:
          `The source introduces a DXT / extension privilege-bridge ` +
          `(${site.kind}) that elevates ${site.marker} without a ` +
          `user confirmation gate — matching the 2025 CVE chain.`,
      })
      .propagation({
        propagation_type: "cross-tool-flow",
        location: site.location,
        observed:
          `Privilege crosses the extension / IPC boundary into the ` +
          `MCP tool surface.`,
      })
      .sink({
        sink_type: "privilege-grant",
        location: site.location,
        observed: `${site.kind} ingress: ${site.marker}`,
        cve_precedent:
          site.kind === "auto-approve-flag"
            ? "CVE-2025-54136"
            : site.kind === "native-messaging-bridge"
              ? "CVE-2025-54135"
              : "CVE-2025-59536",
      })
      .impact({
        impact_type: "privilege-escalation",
        scope: "connected-services",
        exploitability: "trivial",
        scenario:
          `The ingress grants the caller trusted access to every MCP ` +
          `tool the server exposes. No user-facing prompt intervenes, ` +
          `so a single compromised extension / config commit becomes ` +
          `RCE against the user's workspace.`,
      })
      .factor(
        "dxt_privilege_bridge_observed",
        0.14,
        `AST classification matched ${site.kind} via the shared ` +
          `DATA_EXFIL_SINKS vocabulary (${STRATEGY_SHARED_VOCAB}).`,
      )
      .factor(
        "no_user_confirmation_gate",
        0.08,
        `The ingress has no visible consent prompt before the trusted ` +
          `action executes.`,
      );

    builder.reference({
      id:
        site.kind === "auto-approve-flag"
          ? "CVE-2025-54136"
          : site.kind === "native-messaging-bridge"
            ? "CVE-2025-54135"
            : "CVE-2025-59536",
      title: `2025 DXT / MCP config CVE (${site.kind})`,
      url:
        site.kind === "auto-approve-flag"
          ? "https://nvd.nist.gov/vuln/detail/CVE-2025-54136"
          : site.kind === "native-messaging-bridge"
            ? "https://nvd.nist.gov/vuln/detail/CVE-2025-54135"
            : "https://nvd.nist.gov/vuln/detail/CVE-2025-59536",
      relevance:
        "Disclosed 2025 vulnerability demonstrating the exact ingress " +
        "shape this finding detects.",
    });

    builder.verification(stepInspectSite(site));
    builder.verification(stepCheckCveContext(site));

    const chain = builder.build();
    return capConfidence(chain, CONFIDENCE_CAP);
  }
}

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `Q7 charter caps confidence at ${cap}. Legitimate admin tooling ` +
      `may use ipcMain handlers behind proper consent dialogs; static ` +
      `analysis cannot see the dialog UI.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new DxtPrivilegeChainRule());

export { DxtPrivilegeChainRule };
