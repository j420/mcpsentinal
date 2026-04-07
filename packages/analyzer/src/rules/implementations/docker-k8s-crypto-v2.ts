/**
 * L3, K19, P8, P9, P10 — Docker/K8s/Crypto structural rules (TypedRuleV2)
 *
 * L3:  Dockerfile Base Image Risk — structural FROM parsing
 * K19: Missing Runtime Sandbox — container security config parsing
 * P8:  ECB Mode / Static IV — AST crypto pattern detection
 * P9:  Excessive Container Resources — resource config parsing
 * P10: Network Host Mode — network config parsing
 */

import ts from "typescript";
import type { AnalysisContext } from "../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../base.js";
import { EvidenceChainBuilder } from "../../evidence.js";

function isTestFile(s: string) { return /(?:__tests?__|\.(?:test|spec)\.)/.test(s); }

// ═══════════════════════════════════════════════════════════════════════════════
// L3 — Dockerfile Base Image Risk
// ═══════════════════════════════════════════════════════════════════════════════

interface FromInstruction {
  line: number;
  raw: string;
  image: string;
  tag: string | null;
  digest: string | null;
  stage: string | null;
}

function parseDockerfileFroms(source: string): FromInstruction[] {
  const results: FromInstruction[] = [];
  const lines = source.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    // FROM [--platform=...] image[:tag|@digest] [AS stage]
    const match = line.match(/^FROM\s+(?:--\w+=\S+\s+)?(\S+?)(?::(\S+?))?(?:@(\S+))?\s*(?:AS\s+(\S+))?$/i);
    if (!match) continue;
    results.push({
      line: i + 1,
      raw: line,
      image: match[1],
      tag: match[2] || null,
      digest: match[3] || null,
      stage: match[4] || null,
    });
  }
  return results;
}

const MUTABLE_TAGS = /^(latest|stable|lts|edge|nightly|dev|beta|alpha|rc|canary|next|current|mainline)$/i;

class L3Rule implements TypedRuleV2 {
  readonly id = "L3";
  readonly name = "Dockerfile Base Image Risk";
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    if (!context.source_code || isTestFile(context.source_code)) return [];
    const source = context.source_code;
    const froms = parseDockerfileFroms(source);
    if (froms.length === 0) return [];

    const findings: RuleResult[] = [];
    for (const f of froms) {
      if (f.image === "scratch") continue;  // scratch is safe
      if (f.digest) continue;  // SHA256 pinned — safe

      let issue: string | null = null;
      let severity: "high" | "medium" = "high";

      if (!f.tag) {
        issue = `Base image "${f.image}" has no tag (defaults to :latest)`;
      } else if (MUTABLE_TAGS.test(f.tag)) {
        issue = `Base image "${f.image}:${f.tag}" uses mutable tag "${f.tag}"`;
      }

      if (!issue) continue;

      // Check for digest pin elsewhere in multi-stage
      const hasAnyDigest = froms.some(x => x.digest);

      const builder = new EvidenceChainBuilder()
        .source({
          source_type: "file-content",
          location: `Dockerfile line ${f.line}`,
          observed: f.raw.slice(0, 120),
          rationale:
            `${issue}. Mutable tags can be silently replaced by a compromised registry, ` +
            `pulling in backdoored base images without any change in the Dockerfile.`,
        })
        .propagation({
          propagation_type: "direct-pass",
          location: `FROM instruction at line ${f.line}`,
          observed: "Base image tag resolves to different image content over time",
        })
        .sink({
          sink_type: "code-evaluation",
          location: `container built from line ${f.line}`,
          observed: `Container inherits all binaries/libraries from unpinned base image`,
        })
        .mitigation({
          mitigation_type: "input-validation",
          present: hasAnyDigest,
          location: "Dockerfile",
          detail: hasAnyDigest
            ? "Some FROM instructions use digest pinning"
            : "No digest pinning found in any FROM instruction",
        })
        .impact({
          impact_type: "remote-code-execution",
          scope: "server-host",
          exploitability: "moderate",
          scenario:
            `Attacker compromises registry or performs tag mutation attack. ` +
            `Next build pulls backdoored image. All container workloads execute attacker code.`,
        })
        .factor("mutable_base_tag", 0.10, issue)
        .factor("no_digest_pin", f.digest ? -0.15 : 0.08, f.digest ? "SHA256 digest present" : "No SHA256 digest pinning")
        .reference({
          id: "AML.T0017",
          title: "MITRE ATLAS AML.T0017 — Supply Chain Compromise",
          relevance: "Base image tag mutation is a supply chain attack vector.",
        })
        .verification({
          step_type: "check-config",
          instruction: `Verify line ${f.line}: "${f.raw}". Pin to digest: FROM ${f.image}@sha256:<digest>`,
          target: `source_code:${f.line}`,
          expected_observation: "FROM instruction without SHA256 digest pin",
        });

      findings.push({
        rule_id: "L3",
        severity,
        owasp_category: "MCP10-supply-chain",
        mitre_technique: "AML.T0017",
        remediation: "Pin base images to SHA256 digests: FROM image@sha256:abc123...",
        chain: builder.build(),
      });
    }
    return findings;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// K19 — Missing Runtime Sandbox
// ═══════════════════════════════════════════════════════════════════════════════

const SANDBOX_DISABLE_PATTERNS: Array<{ regex: RegExp; desc: string; weight: number }> = [
  { regex: /--privileged\b/, desc: "Docker --privileged flag (full host access)", weight: 0.90 },
  { regex: /--cap-add[=\s]+(?:SYS_ADMIN|ALL)\b/i, desc: "Dangerous capability added (SYS_ADMIN/ALL)", weight: 0.85 },
  { regex: /privileged\s*[:=]\s*(?:true|yes|1)\b/i, desc: "Container privileged mode enabled", weight: 0.88 },
  { regex: /seccomp\s*[:=]\s*['"]?(?:unconfined|disabled)\b/i, desc: "Seccomp profile disabled", weight: 0.82 },
  { regex: /apparmor\s*[:=]\s*['"]?(?:unconfined|disabled|off)\b/i, desc: "AppArmor profile disabled", weight: 0.80 },
  { regex: /selinux\s*[:=]\s*['"]?(?:disabled|permissive|off|false)\b/i, desc: "SELinux disabled or permissive", weight: 0.78 },
  { regex: /--security-opt\s*[=\s]*['"]?no-new-privileges\s*[:=]\s*false/i, desc: "no-new-privileges disabled", weight: 0.75 },
  { regex: /readOnlyRootFilesystem\s*[:=]\s*false\b/i, desc: "Read-only root filesystem disabled", weight: 0.60 },
  { regex: /allowPrivilegeEscalation\s*[:=]\s*true\b/i, desc: "Privilege escalation allowed", weight: 0.78 },
  { regex: /--pid[=\s]+host\b/i, desc: "Host PID namespace (can see all host processes)", weight: 0.75 },
];

const SANDBOX_MITIGATIONS = [
  /seccomp\s*[:=]\s*['"]?(?:runtime|localhost)/i,
  /apparmor\s*[:=]\s*['"]?(?:runtime|localhost)/i,
  /readOnlyRootFilesystem\s*[:=]\s*true/i,
  /runAsNonRoot\s*[:=]\s*true/i,
  /--read-only\b/,
  /--cap-drop[=\s]+ALL/i,
];

class K19Rule implements TypedRuleV2 {
  readonly id = "K19";
  readonly name = "Missing Runtime Sandbox";
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    if (!context.source_code || isTestFile(context.source_code)) return [];
    const source = context.source_code;
    const findings: RuleResult[] = [];

    for (const { regex, desc, weight } of SANDBOX_DISABLE_PATTERNS) {
      regex.lastIndex = 0;
      const match = regex.exec(source);
      if (!match) continue;

      const line = source.substring(0, match.index).split("\n").length;
      const lineText = source.split("\n")[line - 1]?.trim() || "";
      if (lineText.startsWith("//") || lineText.startsWith("#") || lineText.startsWith("*")) continue;

      const hasMitigation = SANDBOX_MITIGATIONS.some(p => p.test(source));

      const builder = new EvidenceChainBuilder()
        .source({
          source_type: "file-content",
          location: `line ${line}`,
          observed: match[0].slice(0, 100),
          rationale: `Container security weakened: ${desc}. This removes OS-level isolation between the container and host.`,
        })
        .sink({
          sink_type: "config-modification",
          location: `line ${line}`,
          observed: `Security boundary disabled: ${desc}`,
        })
        .mitigation({
          mitigation_type: "sandbox",
          present: hasMitigation,
          location: "container config",
          detail: hasMitigation
            ? "Some sandbox mitigations detected (read-only FS, cap-drop, etc.)"
            : "No compensating sandbox controls found",
        })
        .impact({
          impact_type: "privilege-escalation",
          scope: "server-host",
          exploitability: weight >= 0.85 ? "trivial" : "moderate",
          scenario:
            `${desc}. Container escape becomes trivial with privileged mode or disabled security profiles. ` +
            `Attacker gains full host access, can read secrets, pivot to other containers.`,
        })
        .factor("sandbox_disabled", weight * 0.12, desc)
        .reference({
          id: "CoSAI-MCP-T8",
          title: "CoSAI MCP Security T8 — Container Runtime Security",
          relevance: "Container security profiles are the primary isolation boundary for MCP servers.",
        })
        .verification({
          step_type: "check-config",
          instruction: `Review line ${line} for container security: "${lineText.slice(0, 80)}"`,
          target: `source_code:${line}`,
          expected_observation: desc,
        });

      findings.push({
        rule_id: "K19",
        severity: "high",
        owasp_category: "MCP07-insecure-config",
        mitre_technique: null,
        remediation: "Enable container sandboxing (seccomp, AppArmor). Never disable security profiles.",
        chain: builder.build(),
      });
    }
    return findings;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// P8 — ECB Mode / Static IV
// ═══════════════════════════════════════════════════════════════════════════════

const ECB_PATTERNS = [/ECB/i, /ecb/];
const STATIC_IV_PATTERNS = [
  /(?:iv|IV|nonce)\s*[:=]\s*(?:['"](?:0{8,}|1{8,}|abc|000)|Buffer\.alloc\s*\(\s*\d+\s*\))/,
  /(?:iv|IV|nonce)\s*[:=]\s*['"][\x00-\x1f]*['"]/,
  /(?:iv|IV|nonce)\s*[:=]\s*new\s+Uint8Array\s*\(\s*\d+\s*\)/,
];
const MATH_RANDOM_CRYPTO = /Math\.random\s*\(\s*\)/;
const CRYPTO_CONTEXT = /(?:key|secret|iv|nonce|salt|token|encrypt|cipher|hmac)/i;
const SAFE_RANDOM = /(?:crypto\.randomBytes|crypto\.getRandomValues|randomUUID|randomFillSync|webcrypto)/i;

class P8Rule implements TypedRuleV2 {
  readonly id = "P8";
  readonly name = "ECB Mode / Static IV";
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    if (!context.source_code || isTestFile(context.source_code)) return [];
    const source = context.source_code;
    const findings: RuleResult[] = [];

    try {
      const sf = ts.createSourceFile("scan.ts", source, ts.ScriptTarget.Latest, true);

      const visit = (node: ts.Node): void => {
        // Check string literals for ECB mode
        if (ts.isStringLiteral(node)) {
          const val = node.text;
          if (ECB_PATTERNS.some(p => p.test(val)) && /(?:aes|des|cipher|encrypt)/i.test(val)) {
            const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
            findings.push(this.buildFinding("ecb_mode", `ECB mode cipher: "${val}"`, line, source));
          }
        }

        // Check variable declarations for static IV
        if (ts.isVariableDeclaration(node) && node.initializer) {
          const name = node.name.getText(sf).toLowerCase();
          if (/^(?:iv|nonce|salt)$/.test(name) || /(?:_iv|_nonce|_salt)$/.test(name)) {
            const initText = node.initializer.getText(sf);
            const isStatic = STATIC_IV_PATTERNS.some(p => p.test(`${name} = ${initText}`)) ||
              (ts.isCallExpression(node.initializer) && /Buffer\.alloc|new\s+Uint8Array/.test(initText) && !/random/i.test(initText));
            if (isStatic) {
              const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
              findings.push(this.buildFinding("static_iv", `Static IV/nonce: ${name} = ${initText.slice(0, 60)}`, line, source));
            }
          }
        }

        // Check Math.random() in crypto context
        if (ts.isCallExpression(node)) {
          const callText = node.expression.getText(sf);
          if (MATH_RANDOM_CRYPTO.test(callText + "()")) {
            const enclosing = this.getEnclosingFunc(node, sf);
            if (enclosing) {
              const funcText = enclosing.getText(sf);
              if (CRYPTO_CONTEXT.test(funcText) && !SAFE_RANDOM.test(funcText)) {
                const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
                findings.push(this.buildFinding("math_random_crypto", "Math.random() used in cryptographic context", line, source));
              }
            }
          }
        }

        ts.forEachChild(node, visit);
      };

      ts.forEachChild(sf, visit);
    } catch { /* AST failure */ }
    return findings;
  }

  private getEnclosingFunc(node: ts.Node, _sf: ts.SourceFile): ts.Node | null {
    let cur: ts.Node | undefined = node.parent;
    while (cur) {
      if (ts.isFunctionDeclaration(cur) || ts.isFunctionExpression(cur) ||
          ts.isArrowFunction(cur) || ts.isMethodDeclaration(cur)) return cur;
      cur = cur.parent;
    }
    return null;
  }

  private buildFinding(type: string, desc: string, line: number, source: string): RuleResult {
    const lineText = source.split("\n")[line - 1]?.trim() || "";
    const hasSafeRandom = SAFE_RANDOM.test(source);

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: `line ${line}`,
        observed: lineText.slice(0, 120),
        rationale: `Insecure cryptographic pattern: ${desc}. ${
          type === "ecb_mode" ? "ECB mode preserves plaintext patterns — identical blocks produce identical ciphertext." :
          type === "static_iv" ? "Static IVs allow pattern analysis across encryptions and enable known-plaintext attacks." :
          "Math.random() is not cryptographically secure — predictable seed enables key/IV recovery."
        }`,
      })
      .sink({
        sink_type: "credential-exposure",
        location: `line ${line}`,
        observed: `Weak cryptography: ${desc}`,
      })
      .mitigation({
        mitigation_type: "sanitizer-function",
        present: hasSafeRandom,
        location: "file scope",
        detail: hasSafeRandom ? "crypto.randomBytes or similar CSPRNG found in file" : "No CSPRNG usage detected",
      })
      .impact({
        impact_type: "data-exfiltration",
        scope: "user-data",
        exploitability: "complex",
        scenario:
          `${desc}. Encrypted data is vulnerable: ECB leaks patterns, static IVs enable ` +
          `cross-message analysis, Math.random() seeds are predictable.`,
      })
      .factor(type, 0.10, desc)
      .reference({
        id: "CWE-327",
        title: "CWE-327 — Use of a Broken or Risky Cryptographic Algorithm",
        relevance: "ECB mode, static IVs, and weak PRNGs are all classified as broken crypto.",
      })
      .verification({
        step_type: "inspect-source",
        instruction: `Review line ${line}: "${lineText.slice(0, 80)}". Verify cryptographic weakness.`,
        target: `source_code:${line}`,
        expected_observation: desc,
      });

    return {
      rule_id: "P8",
      severity: "high",
      owasp_category: "MCP07-insecure-config",
      mitre_technique: null,
      remediation: "Use CBC/GCM mode. Generate random IVs with crypto.randomBytes(). Never use Math.random() for crypto.",
      chain: builder.build(),
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// P9 — Excessive Container Resources
// ═══════════════════════════════════════════════════════════════════════════════

const EXCESSIVE_RESOURCE_PATTERNS: Array<{ regex: RegExp; desc: string }> = [
  { regex: /(?:memory|mem_limit|memoryLimit)\s*[:=]\s*['"]?(?:unlimited|0)\s*(?:['"])?/gi, desc: "unlimited memory allocation" },
  { regex: /(?:memory|mem_limit|memoryLimit)\s*[:=]\s*['"]?(\d+)\s*(?:Gi|GB)/gi, desc: "excessive memory (>16GB)" },
  { regex: /(?:cpu|cpuLimit|cpu_limit)\s*[:=]\s*['"]?(?:unlimited|0)\s*(?:['"])?$/gim, desc: "unlimited CPU allocation" },
  { regex: /--memory[=\s]+0\b/, desc: "Docker --memory=0 (unlimited)" },
  { regex: /--cpus[=\s]+0\b/, desc: "Docker --cpus=0 (unlimited)" },
  { regex: /(?:pids_limit|pidsLimit)\s*[:=]\s*['"]?(?:-1|unlimited|0)/gi, desc: "unlimited PIDs (fork bomb risk)" },
  { regex: /(?:ulimit|nofile)\s*[:=]\s*['"]?(?:unlimited|-1|1048576)/gi, desc: "excessive ulimit" },
];

class P9Rule implements TypedRuleV2 {
  readonly id = "P9";
  readonly name = "Excessive Container Resource Limits";
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    if (!context.source_code || isTestFile(context.source_code)) return [];
    const source = context.source_code;
    const findings: RuleResult[] = [];

    for (const { regex, desc } of EXCESSIVE_RESOURCE_PATTERNS) {
      regex.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = regex.exec(source)) !== null) {
        // For memory with numeric value, check if > 16GB
        if (desc.includes(">16GB") && match[1]) {
          const gb = parseInt(match[1], 10);
          if (gb <= 16) continue;
        }

        const line = source.substring(0, match.index).split("\n").length;
        const lineText = source.split("\n")[line - 1]?.trim() || "";
        if (lineText.startsWith("//") || lineText.startsWith("#") || lineText.startsWith("*")) continue;

        const builder = new EvidenceChainBuilder()
          .source({
            source_type: "file-content",
            location: `line ${line}`,
            observed: match[0].slice(0, 100),
            rationale: `Container resource misconfiguration: ${desc}. Unlimited resources enable denial-of-service attacks.`,
          })
          .sink({
            sink_type: "config-modification",
            location: `line ${line}`,
            observed: `Resource limit missing or excessive: ${desc}`,
          })
          .impact({
            impact_type: "denial-of-service",
            scope: "server-host",
            exploitability: "moderate",
            scenario:
              `${desc}. A compromised container can consume all host resources, ` +
              `causing denial of service for all co-located services.`,
          })
          .factor("excessive_resources", 0.08, desc)
          .reference({
            id: "CoSAI-MCP-T10",
            title: "CoSAI MCP Security T10 — Resource Exhaustion Prevention",
            relevance: "Unlimited container resources enable DoS attacks on the host.",
          })
          .verification({
            step_type: "check-config",
            instruction: `Review resource limit at line ${line}: "${lineText.slice(0, 80)}"`,
            target: `source_code:${line}`,
            expected_observation: desc,
          });

        findings.push({
          rule_id: "P9",
          severity: "high",
          owasp_category: "MCP07-insecure-config",
          mitre_technique: null,
          remediation: "Set reasonable resource limits for containers. Unlimited resources enable DoS attacks.",
          chain: builder.build(),
        });
        break;  // One finding per pattern type
      }
    }
    return findings;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// P10 — Network Host Mode
// ═══════════════════════════════════════════════════════════════════════════════

const HOST_NETWORK_PATTERNS: Array<{ regex: RegExp; desc: string }> = [
  { regex: /network_mode\s*[:=]\s*['"]?host['"]?/gi, desc: "Docker Compose host network mode" },
  { regex: /networkMode\s*[:=]\s*['"]?host['"]?/gi, desc: "Kubernetes host network mode" },
  { regex: /--net(?:work)?[=\s]+host\b/gi, desc: "Docker CLI host network flag" },
  { regex: /hostNetwork\s*[:=]\s*(?:true|yes|1)\b/gi, desc: "Kubernetes hostNetwork: true" },
  { regex: /network\.mode\s*[:=]\s*['"]?host/gi, desc: "Container runtime host network config" },
];

const NETWORK_MITIGATIONS = [
  /network_mode\s*[:=]\s*['"]?(?:bridge|overlay|none|internal)/i,
  /networkPolicy/i,
  /--network[=\s]+(?!host)\S+/i,
];

class P10Rule implements TypedRuleV2 {
  readonly id = "P10";
  readonly name = "Network Host Mode";
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    if (!context.source_code || isTestFile(context.source_code)) return [];
    const source = context.source_code;
    const findings: RuleResult[] = [];

    for (const { regex, desc } of HOST_NETWORK_PATTERNS) {
      regex.lastIndex = 0;
      const match = regex.exec(source);
      if (!match) continue;

      const line = source.substring(0, match.index).split("\n").length;
      const lineText = source.split("\n")[line - 1]?.trim() || "";
      if (lineText.startsWith("//") || lineText.startsWith("#") || lineText.startsWith("*")) continue;

      const hasNetworkPolicy = NETWORK_MITIGATIONS.some(p => p.test(source));

      const builder = new EvidenceChainBuilder()
        .source({
          source_type: "file-content",
          location: `line ${line}`,
          observed: match[0].slice(0, 100),
          rationale:
            `${desc}. Host network mode removes network isolation — the container shares the host's ` +
            `network stack, can bind to any host port, and can intercept host network traffic.`,
        })
        .sink({
          sink_type: "config-modification",
          location: `line ${line}`,
          observed: `Network isolation disabled: ${desc}`,
        })
        .mitigation({
          mitigation_type: "sandbox",
          present: hasNetworkPolicy,
          location: "container config",
          detail: hasNetworkPolicy
            ? "Network policies or bridge mode detected elsewhere"
            : "No network isolation controls found",
        })
        .impact({
          impact_type: "privilege-escalation",
          scope: "server-host",
          exploitability: "moderate",
          scenario:
            `${desc}. Container can: (1) bind to host ports, hijacking services, ` +
            `(2) access host-only services (127.0.0.1), (3) sniff host network traffic, ` +
            `(4) pivot to other containers via host network.`,
        })
        .factor("host_network", 0.12, desc)
        .reference({
          id: "CoSAI-MCP-T8",
          title: "CoSAI MCP Security T8 — Container Runtime Security",
          relevance: "Host network mode bypasses container network isolation.",
        })
        .verification({
          step_type: "check-config",
          instruction: `Review line ${line}: "${lineText.slice(0, 80)}". Container uses host networking.`,
          target: `source_code:${line}`,
          expected_observation: desc,
        });

      findings.push({
        rule_id: "P10",
        severity: "high",
        owasp_category: "MCP07-insecure-config",
        mitre_technique: null,
        remediation: "Use bridge or overlay networks. Host network mode exposes all host ports to the container.",
        chain: builder.build(),
      });
    }
    return findings;
  }
}

// Register all rules
registerTypedRuleV2(new L3Rule());
registerTypedRuleV2(new K19Rule());
registerTypedRuleV2(new P8Rule());
registerTypedRuleV2(new P9Rule());
registerTypedRuleV2(new P10Rule());
