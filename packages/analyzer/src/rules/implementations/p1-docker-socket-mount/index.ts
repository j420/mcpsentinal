/**
 * P1 — Docker Socket Mount in Container (v2)
 *
 * One finding per socket-reference line. Confidence cap 0.85 — daemon-side
 * AppArmor / SELinux / socket-activation policies can defeat exploitation
 * but the analyzer cannot observe them from source.
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
import { gatherP1, type P1Hit } from "./gather.js";
import {
  stepInspectSocketMount,
  stepRecordConfigPointer,
  stepCheckReadOnlyClaim,
  stepCheckSocketProxyAlternative,
} from "./verification.js";

const RULE_ID = "P1";
const RULE_NAME = "Docker Socket Mount in Container";
const OWASP = "MCP07-insecure-config" as const;
const MITRE = "AML.T0054";
const CONFIDENCE_CAP = 0.85;

const REMEDIATION =
  "Remove the container-runtime socket mount. For list/log-only integrations, " +
  "deploy docker-socket-proxy (tecnativa or linuxserver variants) with minimal " +
  "API verbs enabled. For CI build pipelines, use Kaniko, Buildah, or rootless " +
  "Docker — none require daemon access. For workloads that truly need " +
  "orchestration, place them on a dedicated management node with explicit " +
  "risk acceptance and AppArmor / SELinux profiles restricting the Docker API. " +
  "A :ro flag is NOT a mitigation — the daemon accepts create/exec calls " +
  "regardless of inode write permissions.";

class DockerSocketMountRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherP1(context);
    if (gathered.hits.length === 0) return [];
    return gathered.hits.map((hit) => this.buildFinding(hit));
  }

  private buildFinding(hit: P1Hit): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: hit.location,
        observed: hit.observed,
        rationale:
          `${hit.spec.description} Mounting the ${hit.spec.runtime} socket into a ` +
          `workload container hands that container full control of the runtime ` +
          `daemon. The container can create new privileged containers, bind-mount ` +
          `the host filesystem, and pivot to host root.`,
      })
      .propagation({
        propagation_type: "direct-pass",
        location: hit.configLocation,
        observed:
          `${hit.spec.path} is bound as a volume in context "${hit.mountContext}". ` +
          `The socket becomes reachable from inside the container.`,
      })
      .sink({
        sink_type: "privilege-grant",
        location: hit.configLocation,
        observed:
          `Runtime daemon socket reachable from the container — attacker-in-container ` +
          `can call docker-run --privileged -v /:/host and chroot to host root.`,
        cve_precedent: "CVE-2019-5736",
      })
      .impact({
        impact_type: "remote-code-execution",
        scope: "server-host",
        exploitability: "trivial",
        scenario:
          `Prompt injection into an MCP tool with shell access runs ` +
          `docker-run --rm --privileged -v /:/host --entrypoint chroot <image> /host sh. ` +
          `Three shell lines later the attacker has root on the host, including ` +
          `every sibling container's process space and the kubelet's credentials.`,
      })
      .factor(
        "socket_path_variant",
        hit.spec.weight * 0.12,
        `Socket variant: ${hit.spec.id} (${hit.spec.runtime}).`,
      )
      .factor(
        "mount_context",
        0.04,
        `Mount context token matched: ${hit.mountContext}.`,
      )
      .factor(
        "readonly_flag_present",
        hit.readonlyFlag ? -0.02 : 0,
        hit.readonlyFlag
          ? `:ro / readOnly: true present — does NOT meaningfully reduce risk ` +
            `(Docker API is independent of inode permissions). Tiny negative ` +
            `adjustment reflects operator intent, not exploit-path closure.`
          : `No read-only flag — full writable access over the socket.`,
      )
      .reference({
        id: "CVE-2019-5736",
        title: "runC container escape via /proc/self/exe overwrite",
        url: "https://nvd.nist.gov/vuln/detail/CVE-2019-5736",
        relevance:
          "CVE-2019-5736 is the canonical precedent: once a container has a " +
          "privileged-enough primitive, escape to host root is deterministic. " +
          "Mounting docker.sock supplies that primitive directly — the attacker " +
          "does not even need a runC vulnerability; they spawn a privileged " +
          "container via the Docker API.",
      })
      .verification(stepInspectSocketMount(hit))
      .verification(stepRecordConfigPointer(hit))
      .verification(stepCheckReadOnlyClaim(hit))
      .verification(stepCheckSocketProxyAlternative(hit));

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
      `P1 charter caps confidence at ${cap} — daemon-side AppArmor / SELinux ` +
      `profiles or socket-activation policies can defeat the escape path out-of-file.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new DockerSocketMountRule());

export { DockerSocketMountRule };
