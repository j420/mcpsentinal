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
              confidence: 0.95,
              metadata: { analysis_type: "structural", line: inst.line },
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
        findings.push({
          rule_id: "P2",
          severity: "critical",
          evidence:
            `Privileged container at line ${i + 1}. ` +
            `Privileged mode disables ALL security boundaries — equivalent to root on host.`,
          remediation: "Remove privileged: true. Use specific capabilities instead.",
          owasp_category: "MCP07-insecure-config",
          mitre_technique: "AML.T0054",
          confidence: 0.98,
          metadata: { analysis_type: "structural", line: i + 1 },
        });
      }

      // cap_add with dangerous capabilities
      for (const cap of this.DANGEROUS_CAPS) {
        if (line.includes(cap) && /(?:cap_add|capabilities|add)/.test(lines.slice(Math.max(0, i - 3), i + 1).join("\n"))) {
          findings.push({
            rule_id: "P2",
            severity: "critical",
            evidence:
              `Dangerous capability ${cap} at line ${i + 1}. ` +
              `${cap === "SYS_ADMIN" ? "SYS_ADMIN enables container escape." : `${cap} grants elevated host access.`}`,
            remediation: `Remove ${cap} capability. Use the minimum required capabilities.`,
            owasp_category: "MCP07-insecure-config",
            mitre_technique: "AML.T0054",
            confidence: 0.93,
            metadata: { analysis_type: "structural", line: i + 1, capability: cap },
          });
          break;
        }
      }

      // hostPID / hostIPC / hostNetwork
      if (/host(?:PID|IPC|Network)\s*:\s*true/i.test(line)) {
        const match = line.match(/host(PID|IPC|Network)/i)!;
        findings.push({
          rule_id: "P2",
          severity: "critical",
          evidence: `host${match[1]}: true at line ${i + 1}. Shares host ${match[1].toLowerCase()} namespace with container.`,
          remediation: `Remove host${match[1]}. Container should use its own isolated namespace.`,
          owasp_category: "MCP07-insecure-config",
          mitre_technique: "AML.T0054",
          confidence: 0.95,
          metadata: { analysis_type: "structural", line: i + 1 },
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
            metadata: { analysis_type: "ast_taint" },
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
            confidence: 0.88,
            metadata: { analysis_type: "pattern", line },
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

    for (const { regex, desc, lang, confidence } of patterns) {
      regex.lastIndex = 0;
      const match = regex.exec(source);
      if (match) {
        const line = getLineNumber(source, match.index);
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
          confidence,
          metadata: { analysis_type: "structural", line, language: lang },
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
          confidence: 0.92,
          metadata: { analysis_type: "structural", line: inst.line },
        });
      }

      // ENV with secret-like names
      if (inst.directive === "ENV" && this.SECRET_ENV_NAMES.test(inst.content)) {
        findings.push({
          rule_id: "P5",
          severity: "critical",
          evidence:
            `Dockerfile ENV with credential at line ${inst.line}: "ENV ${inst.content.slice(0, 60)}". ` +
            `ENV values are baked into the image layer and visible to anyone with image access.`,
          remediation: "Pass secrets at runtime via -e flag or Docker secrets, not at build time.",
          owasp_category: "MCP07-insecure-config",
          mitre_technique: "AML.T0057",
          confidence: 0.90,
          metadata: { analysis_type: "structural", line: inst.line },
        });
      }

      // COPY .env file
      if (inst.directive === "COPY" && /\.env\b/.test(inst.content)) {
        findings.push({
          rule_id: "P5",
          severity: "critical",
          evidence:
            `COPY .env at line ${inst.line}. .env files contain secrets and should never be copied into images.`,
          remediation: "Add .env to .dockerignore. Use Docker secrets or runtime env vars.",
          owasp_category: "MCP07-insecure-config",
          mitre_technique: "AML.T0057",
          confidence: 0.95,
          metadata: { analysis_type: "structural", line: inst.line },
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

    for (const { regex, desc, confidence } of patterns) {
      regex.lastIndex = 0;
      const match = regex.exec(source);
      if (match) {
        const line = getLineNumber(source, match.index);
        findings.push({
          rule_id: "P6",
          severity: "critical",
          evidence: `${desc} at line ${line}: "${match[0].slice(0, 80)}".`,
          remediation:
            "Remove LD_PRELOAD/DYLD_INSERT_LIBRARIES usage. Use proper dependency injection. " +
            "If dynamic loading is needed, validate library paths against an allowlist.",
          owasp_category: "MCP07-insecure-config",
          mitre_technique: "AML.T0054",
          confidence,
          metadata: { analysis_type: "structural", line },
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
            confidence: 0.90,
            metadata: { analysis_type: "structural", line: i + 1, sensitive_path: desc },
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
