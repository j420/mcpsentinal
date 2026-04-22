/**
 * P6 — LD_PRELOAD and Shared Library Hijacking (v2)
 *
 * One finding per distinct hijack site. Confidence cap 0.85 — hard-
 * coded trusted-library loads are legitimate and the analyzer cannot
 * always distinguish them from attacker-controlled paths without
 * deeper taint analysis.
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
import { gatherP6, type P6Hit } from "./gather.js";
import {
  stepInspectHijackSite,
  stepRecordConfigPointer,
  stepCheckPathControl,
  stepCheckAlternativePattern,
} from "./verification.js";

const RULE_ID = "P6";
const RULE_NAME = "LD_PRELOAD and Shared Library Hijacking";
const OWASP = "MCP07-insecure-config" as const;
const MITRE = "AML.T0054";
const CONFIDENCE_CAP = 0.85;

const REMEDIATION =
  "Remove the LD_PRELOAD / DYLD_INSERT_LIBRARIES assignment, the " +
  "/etc/ld.so.preload write, or the variable-path dlopen call. If library " +
  "preloading is genuinely required (e.g., OpenTelemetry auto-instrumentation, " +
  "jemalloc allocator swap), ship the library inside the container image, " +
  "ensure the target file is root:root mode 0755, and add file-integrity " +
  "monitoring on the library path. For process-memory access (/proc/PID/mem, " +
  "ptrace), verify the calling code is a legitimate debugger / profiler; MCP " +
  "server code should not reach those primitives in production paths. Drop " +
  "CAP_SYS_PTRACE on the container to prevent this class of attack even if " +
  "the code path is reached.";

class LDPreloadRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherP6(context);
    if (gathered.hits.length === 0) return [];
    return gathered.hits.map((hit) => this.buildFinding(hit));
  }

  private buildFinding(hit: P6Hit): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: hit.location,
        observed: hit.observed,
        rationale: hit.pattern.description,
      })
      .sink({
        sink_type: "code-evaluation",
        location: hit.configLocation,
        observed:
          `Hijack sink: ${hit.pattern.id} — loads arbitrary shared object into ` +
          `target process address space or writes directly to process memory.`,
        cve_precedent: "CVE-2010-3856",
      })
      .impact({
        impact_type: "remote-code-execution",
        scope: "server-host",
        exploitability: hit.variablePath ? "trivial" : "moderate",
        scenario:
          `An attacker with write access to ${
            hit.variablePath ? "the attacker-controlled target path" : "the specified library path"
          } places a malicious shared object. The linker loads it on the next process spawn; ` +
          `the library intercepts every libc call in the target — PAM auth (credential ` +
          `capture), TLS I/O (cleartext tap), exec (command history manipulation). For ` +
          `/etc/ld.so.preload, every binary on the node is affected, including sshd ` +
          `and the container runtime itself.`,
      })
      .factor(
        "hijack_variant",
        hit.pattern.weight * 0.1,
        `Hijack variant: ${hit.pattern.id} (weight ${hit.pattern.weight}).`,
      )
      .factor(
        "attack_scope",
        hit.pattern.id === "ld-so-preload-file" ? 0.1 : 0.04,
        hit.pattern.id === "ld-so-preload-file"
          ? `System-wide scope — every binary loaded on the node is affected.`
          : `Per-process scope — affects processes the env / code path reaches.`,
      )
      .factor(
        "variable_path",
        hit.variablePath ? 0.08 : 0.0,
        hit.variablePath
          ? `Target path is attacker-controllable.`
          : `Target path is a hard-coded literal — operator review for legitimacy.`,
      )
      .reference({
        id: "CVE-2010-3856",
        title: "CVE-2010-3856 — glibc LD_AUDIT / LD_PRELOAD setuid escape",
        url: "https://nvd.nist.gov/vuln/detail/CVE-2010-3856",
        relevance:
          "CVE-2010-3856 demonstrates that even setuid-aware LD_PRELOAD sanitisation " +
          "can be escaped via crafted library paths. Every LD_PRELOAD-honouring " +
          "process is architecturally at risk of an attacker-writable-path hijack.",
      })
      .verification(stepInspectHijackSite(hit))
      .verification(stepRecordConfigPointer(hit))
      .verification(stepCheckPathControl(hit))
      .verification(stepCheckAlternativePattern(hit));

    const chain = capConfidence(builder.build(), CONFIDENCE_CAP);

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

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `P6 charter caps confidence at ${cap} — hard-coded trusted-library loads ` +
      `(libssl, libcrypto) are legitimate and the analyzer cannot always ` +
      `distinguish them from attacker-controlled paths.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new LDPreloadRule());

export { LDPreloadRule };
