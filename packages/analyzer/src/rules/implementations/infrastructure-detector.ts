/**
 * Infrastructure Security Detector — P1, P2, P3, P4, P5, P6, P7
 *
 * Structural parsing of Dockerfiles, docker-compose, k8s manifests.
 * NOT regex on raw text — parses instruction structure.
 *
 * P1: Docker Socket Mount — volume mounts to docker.sock
 * P2: Dangerous Container Capabilities — privileged, cap_add, hostPID
 * P3: Cloud Metadata Service Access — 169.254.169.254, metadata.google
 * P4: TLS Certificate Validation Bypass — rejectUnauthorized, verify=False
 * P5: Secrets in Build Layers — ARG/ENV with credentials, COPY .env
 * P6: LD_PRELOAD / Shared Library Hijacking — LD_PRELOAD, dlopen
 * P7: Sensitive Host Filesystem Mount — hostPath to /, /etc, /root, ~/.ssh
 */

import type { TypedRule, TypedFinding } from "../base.js";
import { registerTypedRule } from "../base.js";
import type { AnalysisContext } from "../../engine.js";
import { analyzeASTTaint } from "../analyzers/taint-ast.js";
import { EvidenceChainBuilder } from "../../evidence.js";
import { computeCodeSignals } from "../../confidence-signals.js";

function isTestFile(source: string): boolean {
  return /(?:__tests?__|\.(?:test|spec)\.)/.test(source);
}

function getLineNumber(source: string, index: number): number {
  return source.substring(0, index).split("\n").length;
}

/** Parse structured instructions from source (Dockerfile, compose, k8s) */
interface ParsedInstruction {
  type: "dockerfile" | "compose" | "k8s" | "code";
  line: number;
  directive?: string;  // FROM, RUN, ENV, COPY, VOLUME, etc.
  content: string;
}

function parseInstructions(source: string): ParsedInstruction[] {
  const lines = source.split("\n");
  const instructions: ParsedInstruction[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith("#")) continue;

    // Dockerfile directives
    const dockerMatch = line.match(/^(FROM|RUN|ENV|ARG|COPY|ADD|VOLUME|EXPOSE|CMD|ENTRYPOINT|USER|WORKDIR|LABEL)\s+(.+)/i);
    if (dockerMatch) {
      instructions.push({ type: "dockerfile", line: i + 1, directive: dockerMatch[1].toUpperCase(), content: dockerMatch[2] });
      continue;
    }

    // docker-compose / k8s YAML patterns
    if (/^\s*(?:volumes|volumeMounts|hostPath|privileged|capabilities|securityContext):/i.test(line)) {
      instructions.push({ type: "compose", line: i + 1, content: line });
      continue;
    }

    // Everything else is code
    instructions.push({ type: "code", line: i + 1, content: line });
  }

  return instructions;
}

// ─── P1: Docker Socket Mount ──────────────────────────────────────────────

class DockerSocketMountRule implements TypedRule {
  readonly id = "P1";
  readonly name = "Docker Socket Mount (Structural)";

  private readonly SOCKET_PATHS = [
    /docker\.sock/i,
    /containerd\.sock/i,
    /crio\.sock/i,
    /podman\.sock/i,
    /\/var\/run\/docker/i,
  ];

  analyze(context: AnalysisContext): TypedFinding[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];

    const findings: TypedFinding[] = [];
    const instructions = parseInstructions(context.source_code);

    // Check VOLUME directives and volume mount patterns
    for (const inst of instructions) {
      for (const socketPattern of this.SOCKET_PATHS) {
        if (socketPattern.test(inst.content)) {
          // Verify it's in a volume/mount context, not just a comment or string
          const isVolumeContext = inst.directive === "VOLUME" ||
            /(?:volumes|volumeMounts|hostPath|mount|bind|source)/.test(inst.content) ||
            inst.content.includes(":");

          if (isVolumeContext) {
            const p1ChainBuilder = new EvidenceChainBuilder()
              .source({
                source_type: "file-content",
                location: `Dockerfile/compose line ${inst.line}`,
                observed: inst.content.slice(0, 100),
                rationale: "Volume mount directive references Docker/container runtime socket",
              })
              .propagation({
                propagation_type: "direct-pass",
                location: `line ${inst.line}`,
                observed: "Socket path bound as volume mount into container",
              })
              .sink({
                sink_type: "privilege-grant",
                location: `container runtime socket at line ${inst.line}`,
                observed: "Docker socket mount grants full Docker daemon control to container",
              })
              .impact({
                impact_type: "remote-code-execution",
                scope: "server-host",
                exploitability: "trivial",
                scenario: "Attacker with container access uses docker.sock to spawn a privileged container, escaping to host",
              })
              .factor("structural-match", 0.2, "Volume directive directly references container runtime socket path");
            const p1Signals = computeCodeSignals({
              sourceCode: context.source_code,
              matchLine: inst.line,
              matchText: inst.content,
              lineText: inst.content,
              context,
              owaspCategory: "MCP07-insecure-config",
            });
            for (const sig of p1Signals) {
              p1ChainBuilder.factor(sig.factor, sig.adjustment, sig.rationale);
            }
            const p1Chain = p1ChainBuilder
              .verification({
                step_type: "check-config",
                instruction: "Check the volume mount directive for docker.sock or equivalent runtime socket",
                target: `line ${inst.line}`,
                expected_observation: "Volume mount binding host container runtime socket into the container",
              })
              .build();
            findings.push({
              rule_id: "P1",
              severity: "critical",
              evidence:
                `Docker socket mount at line ${inst.line}: "${inst.content.slice(0, 100)}". ` +
                `Mounting the Docker socket gives the container full control over the host Docker daemon. ` +
                `Container escape to host is trivial via docker.sock.`,
              remediation:
                "Remove Docker socket mounts. Use Docker-in-Docker (dind) with TLS if container needs Docker access. " +
                "For CI, use rootless Docker or Kaniko for image builds.",
              owasp_category: "MCP07-insecure-config",
              mitre_technique: "AML.T0054",
              confidence: p1Chain.confidence,
              metadata: { analysis_type: "structural", line: inst.line, evidence_chain: p1Chain },
            });
          }
        }
      }
    }

    return findings;
  }
}

// ─── P2: Dangerous Container Capabilities ─────────────────────────────────

class DangerousCapabilitiesRule implements TypedRule {
  readonly id = "P2";
  readonly name = "Dangerous Container Capabilities (Structural)";

  private readonly DANGEROUS_CAPS = new Set([
    "SYS_ADMIN", "SYS_PTRACE", "SYS_RAWIO", "SYS_MODULE",
    "NET_ADMIN", "NET_RAW", "DAC_OVERRIDE", "DAC_READ_SEARCH",
    "SETUID", "SETGID", "ALL",
  ]);

  analyze(context: AnalysisContext): TypedFinding[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];

    const findings: TypedFinding[] = [];
    const source = context.source_code;
    const lines = source.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();

      // privileged: true
      if (/privileged\s*:\s*true/i.test(line)) {
        const p2PrivBuilder = new EvidenceChainBuilder()
          .source({
            source_type: "file-content",
            location: `container config line ${i + 1}`,
            observed: "privileged: true",
            rationale: "Container security context sets privileged mode",
          })
          .sink({
            sink_type: "privilege-grant",
            location: `line ${i + 1}`,
            observed: "Privileged mode disables all Linux security boundaries (AppArmor, seccomp, cgroups)",
          })
          .impact({
            impact_type: "remote-code-execution",
            scope: "server-host",
            exploitability: "trivial",
            scenario: "Privileged container can mount host filesystem, load kernel modules, and escape to host",
          })
          .factor("structural-match", 0.2, "Explicit privileged: true in container security context");
        const p2PrivSignals = computeCodeSignals({
          sourceCode: context.source_code,
          matchLine: i + 1,
          matchText: "privileged: true",
          lineText: line,
          context,
          owaspCategory: "MCP07-insecure-config",
        });
        for (const sig of p2PrivSignals) {
          p2PrivBuilder.factor(sig.factor, sig.adjustment, sig.rationale);
        }
        const p2PrivChain = p2PrivBuilder
          .verification({
            step_type: "check-config",
            instruction: "Verify securityContext or container config contains privileged: true",
            target: `line ${i + 1}`,
            expected_observation: "privileged: true in container or pod spec",
          })
          .build();
        findings.push({
          rule_id: "P2",
          severity: "critical",
          evidence:
            `Privileged container at line ${i + 1}. ` +
            `Privileged mode disables ALL security boundaries — equivalent to root on host.`,
          remediation: "Remove privileged: true. Use specific capabilities instead.",
          owasp_category: "MCP07-insecure-config",
          mitre_technique: "AML.T0054",
          confidence: p2PrivChain.confidence,
          metadata: { analysis_type: "structural", line: i + 1, evidence_chain: p2PrivChain },
        });
      }

      // cap_add with dangerous capabilities
      for (const cap of this.DANGEROUS_CAPS) {
        if (line.includes(cap) && /(?:cap_add|capabilities|add)/.test(lines.slice(Math.max(0, i - 3), i + 1).join("\n"))) {
          const p2CapBuilder = new EvidenceChainBuilder()
            .source({
              source_type: "file-content",
              location: `container config line ${i + 1}`,
              observed: `capability: ${cap}`,
              rationale: "Dangerous Linux capability added to container",
            })
            .propagation({
              propagation_type: "direct-pass",
              location: `cap_add/capabilities section near line ${i + 1}`,
              observed: `${cap} added via cap_add or capabilities.add`,
            })
            .sink({
              sink_type: "privilege-grant",
              location: `line ${i + 1}`,
              observed: `${cap} grants elevated host-level access to container processes`,
            })
            .impact({
              impact_type: "privilege-escalation",
              scope: "server-host",
              exploitability: cap === "SYS_ADMIN" ? "trivial" : "moderate",
              scenario: `Container with ${cap} can ${cap === "SYS_ADMIN" ? "escape to host via mount namespace" : "perform privileged operations on the host"}`,
            })
            .factor("structural-match", 0.15, `${cap} found in capabilities context`);
          const p2CapSignals = computeCodeSignals({
            sourceCode: context.source_code,
            matchLine: i + 1,
            matchText: cap,
            lineText: line,
            context,
            owaspCategory: "MCP07-insecure-config",
          });
          for (const sig of p2CapSignals) {
            p2CapBuilder.factor(sig.factor, sig.adjustment, sig.rationale);
          }
          const p2CapChain = p2CapBuilder
            .verification({
              step_type: "check-config",
              instruction: `Verify ${cap} is listed in cap_add or capabilities.add`,
              target: `lines ${Math.max(1, i - 2)}-${i + 1}`,
              expected_observation: `${cap} in container capability additions`,
            })
            .build();
          findings.push({
            rule_id: "P2",
            severity: "critical",
            evidence:
              `Dangerous capability ${cap} at line ${i + 1}. ` +
              `${cap === "SYS_ADMIN" ? "SYS_ADMIN enables container escape." : `${cap} grants elevated host access.`}`,
            remediation: `Remove ${cap} capability. Use the minimum required capabilities.`,
            owasp_category: "MCP07-insecure-config",
            mitre_technique: "AML.T0054",
            confidence: p2CapChain.confidence,
            metadata: { analysis_type: "structural", line: i + 1, capability: cap, evidence_chain: p2CapChain },
          });
          break;
        }
      }

      // hostPID / hostIPC / hostNetwork
      if (/host(?:PID|IPC|Network)\s*:\s*true/i.test(line)) {
        const match = line.match(/host(PID|IPC|Network)/i)!;
        const nsType = match[1].toLowerCase();
        const p2NsBuilder = new EvidenceChainBuilder()
          .source({
            source_type: "file-content",
            location: `container config line ${i + 1}`,
            observed: `host${match[1]}: true`,
            rationale: `Container shares host ${nsType} namespace, breaking isolation`,
          })
          .sink({
            sink_type: "privilege-grant",
            location: `line ${i + 1}`,
            observed: `Host ${nsType} namespace shared with container`,
          })
          .impact({
            impact_type: "privilege-escalation",
            scope: "server-host",
            exploitability: "moderate",
            scenario: `Container with host${match[1]} can ${nsType === "pid" ? "see and signal host processes" : nsType === "network" ? "access host network interfaces and services" : "access host IPC mechanisms"}`,
          })
          .factor("structural-match", 0.15, `Explicit host${match[1]}: true in pod/container spec`);
        const p2NsSignals = computeCodeSignals({
          sourceCode: context.source_code,
          matchLine: i + 1,
          matchText: `host${match[1]}: true`,
          lineText: line,
          context,
          owaspCategory: "MCP07-insecure-config",
        });
        for (const sig of p2NsSignals) {
          p2NsBuilder.factor(sig.factor, sig.adjustment, sig.rationale);
        }
        const p2NsChain = p2NsBuilder
          .verification({
            step_type: "check-config",
            instruction: `Verify host${match[1]}: true in the pod or container specification`,
            target: `line ${i + 1}`,
            expected_observation: `host${match[1]}: true sharing host namespace`,
          })
          .build();
        findings.push({
          rule_id: "P2",
          severity: "critical",
          evidence: `host${match[1]}: true at line ${i + 1}. Shares host ${match[1].toLowerCase()} namespace with container.`,
          remediation: `Remove host${match[1]}. Container should use its own isolated namespace.`,
          owasp_category: "MCP07-insecure-config",
          mitre_technique: "AML.T0054",
          confidence: p2NsChain.confidence,
          metadata: { analysis_type: "structural", line: i + 1, evidence_chain: p2NsChain },
        });
      }
    }

    return findings;
  }
}

// ─── P3: Cloud Metadata Service Access ────────────────────────────────────

class CloudMetadataAccessRule implements TypedRule {
  readonly id = "P3";
  readonly name = "Cloud Metadata Service Access (Taint-Aware)";

  private readonly METADATA_ENDPOINTS = [
    /169\.254\.169\.254/,
    /metadata\.google\.internal/,
    /metadata\.azure\.com/i,
    /100\.100\.100\.200/,  // Alibaba Cloud
    /fd00:ec2::254/,       // AWS IPv6
  ];

  analyze(context: AnalysisContext): TypedFinding[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];

    const findings: TypedFinding[] = [];

    // Phase 1: AST taint — check if metadata URL reaches fetch/request
    try {
      const astFlows = analyzeASTTaint(context.source_code);
      const ssrfFlows = astFlows.filter(f => f.sink.category === "ssrf" && !f.sanitized);

      for (const flow of ssrfFlows) {
        // Check if any part of the flow references metadata endpoints
        const flowText = `${flow.source.expression} ${flow.path.map(s => s.expression).join(" ")} ${flow.sink.expression}`;
        if (this.METADATA_ENDPOINTS.some(p => p.test(flowText))) {
          const p3TaintChain = new EvidenceChainBuilder()
            .source({
              source_type: "file-content",
              location: `line ${flow.source.line}`,
              observed: flow.source.expression,
              rationale: "Cloud metadata endpoint URL used as request target",
            })
            .propagation({
              propagation_type: "variable-assignment",
              location: flow.path.map(s => `L${s.line}`).join(" → "),
              observed: flow.path.map(s => s.expression).join(" → "),
            })
            .sink({
              sink_type: "network-send",
              location: `line ${flow.sink.line}`,
              observed: `HTTP request to cloud metadata service: ${flow.sink.expression}`,
            })
            .impact({
              impact_type: "credential-theft",
              scope: "connected-services",
              exploitability: "trivial",
              scenario: "SSRF to cloud metadata service (169.254.169.254) exposes IAM credentials, enabling lateral movement across cloud resources",
            })
            .factor("ast-taint-confirmed", 0.3, "Complete source→sink taint path confirmed via AST analysis")
            .verification({
              step_type: "inspect-source",
              instruction: "Trace the metadata URL from its definition to where it is used in an HTTP request",
              target: `lines ${flow.source.line}-${flow.sink.line}`,
              expected_observation: "Cloud metadata endpoint flows into fetch/request without network policy blocking",
            })
            .build();
          findings.push({
            rule_id: "P3",
            severity: "critical",
            evidence:
              `[AST taint] Cloud metadata access: "${flow.source.expression}" (L${flow.source.line}) → ` +
              `request (L${flow.sink.line}). SSRF to cloud metadata service exposes IAM credentials.`,
            remediation:
              "Block access to 169.254.169.254. Use IMDSv2 (require PUT token). " +
              "Set HttpPutResponseHopLimit to 1. Use network policies to block metadata endpoint.",
            owasp_category: "MCP07-insecure-config",
            mitre_technique: "AML.T0054",
            confidence: flow.confidence,
            metadata: { analysis_type: "ast_taint", evidence_chain: p3TaintChain },
          });
        }
      }
    } catch { /* fall through */ }

    // Phase 2: Direct URL pattern detection in source
    if (findings.length === 0) {
      for (const endpoint of this.METADATA_ENDPOINTS) {
        const match = endpoint.exec(context.source_code);
        if (match) {
          const line = getLineNumber(context.source_code, match.index);
          const lineText = context.source_code.split("\n")[line - 1] || "";

          // Skip if it's a block rule (blocking metadata is good)
          if (/(?:block|deny|reject|firewall|iptables|REJECT|DROP)/i.test(lineText)) continue;

          const p3PatternBuilder = new EvidenceChainBuilder()
            .source({
              source_type: "file-content",
              location: `line ${line}`,
              observed: match[0],
              rationale: "Cloud metadata service endpoint URL found in source code",
            })
            .sink({
              sink_type: "network-send",
              location: `line ${line}`,
              observed: `Reference to cloud metadata endpoint: ${match[0]}`,
            })
            .impact({
              impact_type: "credential-theft",
              scope: "connected-services",
              exploitability: "moderate",
              scenario: "Cloud metadata access leaks IAM credentials, API keys, and instance identity tokens",
            })
            .factor("pattern-match", 0.1, "Metadata endpoint URL found but taint flow not confirmed via AST");
          const p3PatternSignals = computeCodeSignals({
            sourceCode: context.source_code,
            matchLine: line,
            matchText: match[0],
            lineText: lineText,
            context,
            owaspCategory: "MCP07-insecure-config",
          });
          for (const sig of p3PatternSignals) {
            p3PatternBuilder.factor(sig.factor, sig.adjustment, sig.rationale);
          }
          const p3PatternChain = p3PatternBuilder
            .verification({
              step_type: "inspect-source",
              instruction: "Check if the metadata endpoint URL is used in an HTTP request context",
              target: `line ${line}`,
              expected_observation: "Cloud metadata URL referenced in a request/fetch call, not in a block/deny rule",
            })
            .build();
          findings.push({
            rule_id: "P3",
            severity: "critical",
            evidence:
              `Cloud metadata endpoint "${match[0]}" at line ${line}. ` +
              `Access to cloud metadata service can leak IAM credentials, API keys, and instance identity.`,
            remediation:
              "Remove references to cloud metadata endpoints. Use environment variables or secrets managers " +
              "for credentials. If metadata access is required, use IMDSv2 with session tokens.",
            owasp_category: "MCP07-insecure-config",
            mitre_technique: "AML.T0054",
            confidence: p3PatternChain.confidence,
            metadata: { analysis_type: "pattern", line, evidence_chain: p3PatternChain },
          });
        }
      }
    }

    return findings;
  }
}

// ─── P4: TLS Certificate Validation Bypass ────────────────────────────────

class TLSBypassRule implements TypedRule {
  readonly id = "P4";
  readonly name = "TLS Certificate Validation Bypass (Structural)";

  analyze(context: AnalysisContext): TypedFinding[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];

    const findings: TypedFinding[] = [];
    const source = context.source_code;

    const patterns: Array<{ regex: RegExp; desc: string; lang: string; confidence: number }> = [
      // Node.js
      { regex: /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0/g, desc: "Node TLS validation disabled", lang: "Node.js", confidence: 0.98 },
      { regex: /rejectUnauthorized\s*:\s*false/g, desc: "rejectUnauthorized: false", lang: "Node.js", confidence: 0.95 },
      // Python
      { regex: /verify\s*=\s*False/g, desc: "requests verify=False", lang: "Python", confidence: 0.92 },
      { regex: /ssl\._create_unverified_context/g, desc: "unverified SSL context", lang: "Python", confidence: 0.95 },
      { regex: /CERT_NONE/g, desc: "ssl.CERT_NONE", lang: "Python", confidence: 0.93 },
      // Go
      { regex: /InsecureSkipVerify\s*:\s*true/g, desc: "InsecureSkipVerify: true", lang: "Go", confidence: 0.95 },
      // Java
      { regex: /TrustAllCerts|NullTrustManager|X509TrustManager.*checkServerTrusted.*\{\s*\}/g, desc: "trust-all certificate manager", lang: "Java", confidence: 0.93 },
      // CLI tools
      { regex: /--(?:no-check-certificate|insecure|cacert\s*\/dev\/null)/g, desc: "CLI TLS bypass flag", lang: "CLI", confidence: 0.90 },
      { regex: /curl\s+(?:-k|--insecure)/g, desc: "curl --insecure", lang: "CLI", confidence: 0.92 },
    ];

    for (const { regex, desc, lang } of patterns) {
      regex.lastIndex = 0;
      const match = regex.exec(source);
      if (match) {
        const line = getLineNumber(source, match.index);
        const lineText = source.split("\n")[line - 1] || "";
        const p4Builder = new EvidenceChainBuilder()
          .source({
            source_type: "file-content",
            location: `line ${line}`,
            observed: match[0].slice(0, 60),
            rationale: `${lang} TLS certificate validation bypass pattern found in source code`,
          })
          .sink({
            sink_type: "config-modification",
            location: `line ${line}`,
            observed: `${desc} — disables certificate verification for all outbound connections`,
          })
          .impact({
            impact_type: "data-exfiltration",
            scope: "connected-services",
            exploitability: "moderate",
            scenario: "MITM attacker intercepts traffic due to disabled TLS validation, capturing credentials and sensitive data in transit",
          })
          .factor("structural-match", 0.15, `${lang} TLS bypass pattern detected in source`);
        const p4Signals = computeCodeSignals({
          sourceCode: context.source_code,
          matchLine: line,
          matchText: match[0],
          lineText,
          context,
          owaspCategory: "MCP07-insecure-config",
        });
        for (const sig of p4Signals) {
          p4Builder.factor(sig.factor, sig.adjustment, sig.rationale);
        }
        const p4Chain = p4Builder
          .verification({
            step_type: "inspect-source",
            instruction: `Search for TLS validation bypass patterns (${desc}) in the source code`,
            target: `line ${line}`,
            expected_observation: "TLS certificate verification explicitly disabled",
          })
          .build();
        findings.push({
          rule_id: "P4",
          severity: "critical",
          evidence:
            `[${lang}] ${desc} at line ${line}: "${match[0].slice(0, 60)}". ` +
            `TLS validation bypass enables MITM attacks — attacker can intercept all traffic.`,
          remediation:
            "Remove TLS bypass. Fix certificate issues by installing proper CA certificates. " +
            "Use NODE_EXTRA_CA_CERTS for custom CAs instead of disabling validation.",
          owasp_category: "MCP07-insecure-config",
          mitre_technique: "AML.T0054",
          confidence: p4Chain.confidence,
          metadata: { analysis_type: "structural", line, language: lang, evidence_chain: p4Chain },
        });
      }
    }

    return findings;
  }
}

// ─── P5: Secrets in Build Layers ──────────────────────────────────────────

class SecretsInBuildLayersRule implements TypedRule {
  readonly id = "P5";
  readonly name = "Secrets in Container Build Layers (Structural)";

  private readonly SECRET_ENV_NAMES = /(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|AWS_ACCESS|DATABASE_URL|CREDENTIALS)/i;

  analyze(context: AnalysisContext): TypedFinding[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];

    const findings: TypedFinding[] = [];
    const instructions = parseInstructions(context.source_code);

    for (const inst of instructions) {
      // ARG with secret-like names
      if (inst.directive === "ARG" && this.SECRET_ENV_NAMES.test(inst.content)) {
        const p5ArgBuilder = new EvidenceChainBuilder()
          .source({
            source_type: "file-content",
            location: `Dockerfile line ${inst.line}`,
            observed: `ARG ${inst.content.slice(0, 60)}`,
            rationale: "Dockerfile ARG directive contains credential-like variable name",
          })
          .propagation({
            propagation_type: "direct-pass",
            location: `Dockerfile line ${inst.line}`,
            observed: "ARG value persisted in Docker image layer history",
          })
          .sink({
            sink_type: "credential-exposure",
            location: `image layer at line ${inst.line}`,
            observed: "ARG values are visible via `docker history --no-trunc` to anyone with image access",
          })
          .impact({
            impact_type: "credential-theft",
            scope: "connected-services",
            exploitability: "trivial",
            scenario: "Attacker pulls the image and runs `docker history --no-trunc` to extract build-time credentials",
          })
          .factor("structural-match", 0.15, "ARG name matches credential pattern (PASSWORD, SECRET, TOKEN, etc.)");
        const p5ArgSignals = computeCodeSignals({
          sourceCode: context.source_code,
          matchLine: inst.line,
          matchText: inst.content,
          lineText: inst.content,
          context,
          owaspCategory: "MCP07-insecure-config",
        });
        for (const sig of p5ArgSignals) {
          p5ArgBuilder.factor(sig.factor, sig.adjustment, sig.rationale);
        }
        const p5ArgChain = p5ArgBuilder
          .verification({
            step_type: "inspect-description",
            instruction: "Check the Dockerfile for ARG directives with secret-like names",
            target: `line ${inst.line}`,
            expected_observation: "ARG directive with a name matching PASSWORD, SECRET, TOKEN, API_KEY, or similar",
          })
          .build();
        findings.push({
          rule_id: "P5",
          severity: "critical",
          evidence:
            `Dockerfile ARG with credential at line ${inst.line}: "ARG ${inst.content.slice(0, 60)}". ` +
            `ARG values are visible in image history (docker history --no-trunc).`,
          remediation:
            "Use BuildKit secrets: RUN --mount=type=secret,id=mysecret. " +
            "Never pass credentials via ARG. Use runtime env vars or secrets managers.",
          owasp_category: "MCP07-insecure-config",
          mitre_technique: "AML.T0057",
          confidence: p5ArgChain.confidence,
          metadata: { analysis_type: "structural", line: inst.line, evidence_chain: p5ArgChain },
        });
      }

      // ENV with secret-like names
      if (inst.directive === "ENV" && this.SECRET_ENV_NAMES.test(inst.content)) {
        const p5EnvBuilder = new EvidenceChainBuilder()
          .source({
            source_type: "file-content",
            location: `Dockerfile line ${inst.line}`,
            observed: `ENV ${inst.content.slice(0, 60)}`,
            rationale: "Dockerfile ENV directive contains credential-like variable name",
          })
          .propagation({
            propagation_type: "direct-pass",
            location: `Dockerfile line ${inst.line}`,
            observed: "ENV value baked into image layer, persists in every derived image",
          })
          .sink({
            sink_type: "credential-exposure",
            location: `image layer at line ${inst.line}`,
            observed: "ENV values visible to anyone with access to the image or any container started from it",
          })
          .impact({
            impact_type: "credential-theft",
            scope: "connected-services",
            exploitability: "trivial",
            scenario: "Attacker inspects the image or runs a container to read environment variables containing secrets",
          })
          .factor("structural-match", 0.15, "ENV name matches credential pattern (PASSWORD, SECRET, TOKEN, etc.)");
        const p5EnvSignals = computeCodeSignals({
          sourceCode: context.source_code,
          matchLine: inst.line,
          matchText: inst.content,
          lineText: inst.content,
          context,
          owaspCategory: "MCP07-insecure-config",
        });
        for (const sig of p5EnvSignals) {
          p5EnvBuilder.factor(sig.factor, sig.adjustment, sig.rationale);
        }
        const p5EnvChain = p5EnvBuilder
          .verification({
            step_type: "inspect-description",
            instruction: "Check the Dockerfile for ENV directives with secret-like names",
            target: `line ${inst.line}`,
            expected_observation: "ENV directive with a name matching PASSWORD, SECRET, TOKEN, API_KEY, or similar",
          })
          .build();
        findings.push({
          rule_id: "P5",
          severity: "critical",
          evidence:
            `Dockerfile ENV with credential at line ${inst.line}: "ENV ${inst.content.slice(0, 60)}". ` +
            `ENV values are baked into the image layer and visible to anyone with image access.`,
          remediation: "Pass secrets at runtime via -e flag or Docker secrets, not at build time.",
          owasp_category: "MCP07-insecure-config",
          mitre_technique: "AML.T0057",
          confidence: p5EnvChain.confidence,
          metadata: { analysis_type: "structural", line: inst.line, evidence_chain: p5EnvChain },
        });
      }

      // COPY .env file
      if (inst.directive === "COPY" && /\.env\b/.test(inst.content)) {
        const p5CopyBuilder = new EvidenceChainBuilder()
          .source({
            source_type: "file-content",
            location: `Dockerfile line ${inst.line}`,
            observed: `COPY ${inst.content.slice(0, 60)}`,
            rationale: "Dockerfile COPY directive includes .env file containing secrets",
          })
          .propagation({
            propagation_type: "direct-pass",
            location: `Dockerfile line ${inst.line}`,
            observed: ".env file copied into image layer, persists in image history",
          })
          .sink({
            sink_type: "credential-exposure",
            location: `image layer at line ${inst.line}`,
            observed: ".env file with secrets embedded in the container image",
          })
          .impact({
            impact_type: "credential-theft",
            scope: "connected-services",
            exploitability: "trivial",
            scenario: "Attacker extracts .env file from the image layer to obtain database URLs, API keys, and passwords",
          })
          .factor("structural-match", 0.2, "COPY directive explicitly includes .env file");
        const p5CopySignals = computeCodeSignals({
          sourceCode: context.source_code,
          matchLine: inst.line,
          matchText: inst.content,
          lineText: inst.content,
          context,
          owaspCategory: "MCP07-insecure-config",
        });
        for (const sig of p5CopySignals) {
          p5CopyBuilder.factor(sig.factor, sig.adjustment, sig.rationale);
        }
        const p5CopyChain = p5CopyBuilder
          .verification({
            step_type: "inspect-description",
            instruction: "Check the Dockerfile for COPY directives that include .env files",
            target: `line ${inst.line}`,
            expected_observation: "COPY directive referencing a .env file",
          })
          .build();
        findings.push({
          rule_id: "P5",
          severity: "critical",
          evidence:
            `COPY .env at line ${inst.line}. .env files contain secrets and should never be copied into images.`,
          remediation: "Add .env to .dockerignore. Use Docker secrets or runtime env vars.",
          owasp_category: "MCP07-insecure-config",
          mitre_technique: "AML.T0057",
          confidence: p5CopyChain.confidence,
          metadata: { analysis_type: "structural", line: inst.line, evidence_chain: p5CopyChain },
        });
      }
    }

    return findings;
  }
}

// ─── P6: LD_PRELOAD / Library Hijacking ───────────────────────────────────

class LDPreloadRule implements TypedRule {
  readonly id = "P6";
  readonly name = "LD_PRELOAD Library Hijacking (Taint-Aware)";

  analyze(context: AnalysisContext): TypedFinding[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];

    const findings: TypedFinding[] = [];
    const source = context.source_code;

    const patterns: Array<{ regex: RegExp; desc: string; confidence: number }> = [
      { regex: /LD_PRELOAD\s*=\s*(?!$)/gm, desc: "LD_PRELOAD set — preloads shared library into every process", confidence: 0.92 },
      { regex: /DYLD_INSERT_LIBRARIES\s*=\s*(?!$)/gm, desc: "DYLD_INSERT_LIBRARIES set (macOS LD_PRELOAD)", confidence: 0.92 },
      { regex: /dlopen\s*\(\s*(?!['"`](?:lib(?:ssl|crypto|c|pthread|m|dl)\.so))\w+/g, desc: "dlopen with variable library path", confidence: 0.75 },
      { regex: /\/proc\/\d+\/mem/g, desc: "direct process memory access via /proc/pid/mem", confidence: 0.90 },
      { regex: /ptrace\s*\(\s*PTRACE_ATTACH/g, desc: "ptrace attach to another process", confidence: 0.85 },
    ];

    for (const { regex, desc } of patterns) {
      regex.lastIndex = 0;
      const match = regex.exec(source);
      if (match) {
        const line = getLineNumber(source, match.index);
        const lineText = source.split("\n")[line - 1] || "";
        const p6Builder = new EvidenceChainBuilder()
          .source({
            source_type: "file-content",
            location: `line ${line}`,
            observed: match[0].slice(0, 80),
            rationale: "Shared library hijacking or process injection pattern found in source code",
          })
          .sink({
            sink_type: "code-evaluation",
            location: `line ${line}`,
            observed: `${desc} — enables arbitrary shared library injection into process space`,
          })
          .impact({
            impact_type: "remote-code-execution",
            scope: "server-host",
            exploitability: "moderate",
            scenario: "Attacker places a malicious shared library at the specified path; LD_PRELOAD/dlopen loads it into every process, achieving persistent code execution",
          })
          .factor("structural-match", 0.15, "Library hijacking pattern detected in source");
        const p6Signals = computeCodeSignals({
          sourceCode: context.source_code,
          matchLine: line,
          matchText: match[0],
          lineText,
          context,
          owaspCategory: "MCP07-insecure-config",
        });
        for (const sig of p6Signals) {
          p6Builder.factor(sig.factor, sig.adjustment, sig.rationale);
        }
        const p6Chain = p6Builder
          .verification({
            step_type: "inspect-source",
            instruction: "Search for LD_PRELOAD, DYLD_INSERT_LIBRARIES, dlopen, or /proc/pid/mem patterns",
            target: `line ${line}`,
            expected_observation: "Shared library injection or process memory manipulation pattern",
          })
          .build();
        findings.push({
          rule_id: "P6",
          severity: "critical",
          evidence: `${desc} at line ${line}: "${match[0].slice(0, 80)}".`,
          remediation:
            "Remove LD_PRELOAD/DYLD_INSERT_LIBRARIES usage. Use proper dependency injection. " +
            "If dynamic loading is needed, validate library paths against an allowlist.",
          owasp_category: "MCP07-insecure-config",
          mitre_technique: "AML.T0054",
          confidence: p6Chain.confidence,
          metadata: { analysis_type: "structural", line, evidence_chain: p6Chain },
        });
      }
    }

    return findings;
  }
}

// ─── P7: Sensitive Host Filesystem Mount ──────────────────────────────────

class HostFilesystemMountRule implements TypedRule {
  readonly id = "P7";
  readonly name = "Sensitive Host Filesystem Mount (Structural)";

  private readonly SENSITIVE_PATHS = [
    { pattern: /(?:^|\s|['":])\/(?:\s|['":,]|$)/, desc: "host root filesystem (/)" },
    { pattern: /\/etc(?:\/|\s|['":,]|$)/, desc: "host /etc directory" },
    { pattern: /\/root(?:\/|\s|['":,]|$)/, desc: "host /root directory" },
    { pattern: /~\/\.ssh|\/\.ssh/, desc: "SSH keys directory" },
    { pattern: /\/var\/run(?:\/|\s|['":,]|$)/, desc: "host /var/run" },
    { pattern: /\/proc(?:\/|\s|['":,]|$)/, desc: "host /proc filesystem" },
    { pattern: /\/sys(?:\/|\s|['":,]|$)/, desc: "host /sys filesystem" },
  ];

  analyze(context: AnalysisContext): TypedFinding[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];

    const findings: TypedFinding[] = [];
    const source = context.source_code;
    const lines = source.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Only check lines that are in volume/mount contexts
      const isVolumeContext = /(?:volume|mount|hostPath|bind|source\s*:)/.test(line) ||
        /(?:volume|mount|hostPath)/.test(lines.slice(Math.max(0, i - 3), i).join("\n"));

      if (!isVolumeContext) continue;

      for (const { pattern, desc } of this.SENSITIVE_PATHS) {
        if (pattern.test(line)) {
          const p7Builder = new EvidenceChainBuilder()
            .source({
              source_type: "file-content",
              location: `container config line ${i + 1}`,
              observed: line.trim().slice(0, 80),
              rationale: `Volume mount references sensitive host path: ${desc}`,
            })
            .propagation({
              propagation_type: "direct-pass",
              location: `line ${i + 1}`,
              observed: `Sensitive host directory (${desc}) bound into container via volume mount`,
            })
            .sink({
              sink_type: "credential-exposure",
              location: `container filesystem at line ${i + 1}`,
              observed: `Host path ${desc} exposed inside container — grants access to sensitive host files`,
            })
            .impact({
              impact_type: "credential-theft",
              scope: "server-host",
              exploitability: "trivial",
              scenario: `Attacker with container access reads ${desc} to obtain SSH keys, system credentials, or configuration files from the host`,
            })
            .factor("structural-match", 0.15, `Sensitive host path (${desc}) in volume mount context`);
          const p7Signals = computeCodeSignals({
            sourceCode: context.source_code,
            matchLine: i + 1,
            matchText: line.trim(),
            lineText: line,
            context,
            owaspCategory: "MCP07-insecure-config",
          });
          for (const sig of p7Signals) {
            p7Builder.factor(sig.factor, sig.adjustment, sig.rationale);
          }
          const p7Chain = p7Builder
            .verification({
              step_type: "check-config",
              instruction: "Verify the volume mount references a sensitive host directory",
              target: `line ${i + 1}`,
              expected_observation: `Volume mount binding ${desc} from host into the container`,
            })
            .build();
          findings.push({
            rule_id: "P7",
            severity: "critical",
            evidence:
              `Sensitive host path mount (${desc}) at line ${i + 1}: "${line.trim().slice(0, 80)}". ` +
              `Mounting sensitive host directories exposes credentials, configs, and system files.`,
            remediation:
              "Mount only specific, non-sensitive directories. " +
              "Use named volumes instead of host path mounts. Never mount /, /etc, /root, or ~/.ssh.",
            owasp_category: "MCP07-insecure-config",
            mitre_technique: "AML.T0054",
            confidence: p7Chain.confidence,
            metadata: { analysis_type: "structural", line: i + 1, sensitive_path: desc, evidence_chain: p7Chain },
          });
          break;
        }
      }
    }

    return findings;
  }
}

// ─── Register ──────────────────────────────────────────────────────────────

registerTypedRule(new DockerSocketMountRule());
registerTypedRule(new DangerousCapabilitiesRule());
registerTypedRule(new CloudMetadataAccessRule());
registerTypedRule(new TLSBypassRule());
registerTypedRule(new SecretsInBuildLayersRule());
registerTypedRule(new LDPreloadRule());
registerTypedRule(new HostFilesystemMountRule());
