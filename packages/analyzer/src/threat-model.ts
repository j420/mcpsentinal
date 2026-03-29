/**
 * Threat Model Registry — Maps server profiles to the specific threats that matter.
 *
 * Problem: Running 177 rules against every server treats a weather API the same
 * as a filesystem server with shell access. This produces noise.
 *
 * Solution: Each attack surface maps to a specific threat model containing:
 * 1. The rules that are relevant (and WHY)
 * 2. The real-world attacks that motivated each rule
 * 3. The evidence standard required for a credible finding
 *
 * A finding is only credible if:
 * - The server has the attack surface the rule targets
 * - The evidence chain meets the minimum standard for that threat
 * - The confidence exceeds the threshold for the severity level
 */

import type { AttackSurface, ServerProfile } from "./profiler.js";

// ─── Threat Definitions ───────────────────────────────────────────────────────

/**
 * A threat backed by real-world intelligence.
 * Every threat must have at least one documented attack or CVE.
 */
export interface ThreatDefinition {
  /** Unique identifier */
  id: string;
  /** Human-readable name */
  name: string;
  /** Which attack surface this threat targets */
  attack_surface: AttackSurface;
  /** Rules that detect this threat (by rule ID) */
  rule_ids: string[];
  /** Minimum evidence standard for a credible finding */
  evidence_standard: EvidenceStandard;
  /** Real-world references backing this threat */
  references: ThreatIntelReference[];
  /** Why this threat matters for MCP specifically (not just general security) */
  mcp_specific_rationale: string;
}

export interface EvidenceStandard {
  /** Minimum number of evidence chain links for a credible finding */
  min_chain_length: number;
  /** Must have a source link? (entry point for untrusted data) */
  requires_source: boolean;
  /** Must have a sink link? (dangerous operation) */
  requires_sink: boolean;
  /** Minimum confidence for this threat to produce a finding */
  min_confidence: number;
  /** Description of what counts as adequate evidence */
  description: string;
}

export interface ThreatIntelReference {
  /** CVE ID, paper ID, or unique identifier */
  id: string;
  /** Title of the reference */
  title: string;
  /** URL */
  url: string;
  /** Year of publication */
  year: number;
  /** How it relates to this threat */
  relevance: string;
}

// ─── Threat Registry ──────────────────────────────────────────────────────────

/**
 * The threat registry: every threat model backed by real-world intelligence.
 *
 * These are NOT theoretical. Each threat has documented real-world attacks.
 * When we add a threat, the standard is: "Show me the CVE or the published attack."
 */
export const THREAT_REGISTRY: ThreatDefinition[] = [
  // ── Code Execution Threats ────────────────────────────────────────────────

  {
    id: "T-EXEC-001",
    name: "Command Injection via Tool Parameters",
    attack_surface: "code-execution",
    rule_ids: ["C1", "C16", "J2"],
    evidence_standard: {
      min_chain_length: 3,
      requires_source: true,
      requires_sink: true,
      min_confidence: 0.60,
      description:
        "Must show: (1) untrusted parameter input, (2) propagation to execution sink, " +
        "(3) absence of sanitization. Regex-only matches without taint flow are informational only.",
    },
    references: [
      {
        id: "CVE-2025-6514",
        title: "mcp-remote OS Command Injection",
        url: "https://nvd.nist.gov/vuln/detail/CVE-2025-6514",
        year: 2025,
        relevance: "CVSS 9.6 — OS command injection in mcp-remote package via unsanitized tool parameter",
      },
      {
        id: "CVE-2025-68143",
        title: "Anthropic mcp-server-git Path Validation Bypass",
        url: "https://nvd.nist.gov/vuln/detail/CVE-2025-68143",
        year: 2025,
        relevance: "Three-CVE chain: git_init on .ssh → malicious .git/config → RCE via core.sshCommand",
      },
    ],
    mcp_specific_rationale:
      "MCP tool parameters are filled by AI based on user prompts. The AI is the unwitting " +
      "intermediary — it constructs the dangerous input. Unlike web forms, there is no browser " +
      "validation layer between user intent and server execution.",
  },

  {
    id: "T-EXEC-002",
    name: "Unsafe Deserialization",
    attack_surface: "code-execution",
    rule_ids: ["C12"],
    evidence_standard: {
      min_chain_length: 2,
      requires_source: false,
      requires_sink: true,
      min_confidence: 0.55,
      description:
        "Must show: (1) use of unsafe deserialization function (pickle.loads, yaml.load, " +
        "node-serialize), (2) evidence that input is not from a trusted internal source. " +
        "Presence of SafeLoader/safe_load is a valid mitigation.",
    },
    references: [
      {
        id: "CVE-2017-5941",
        title: "node-serialize Remote Code Execution",
        url: "https://nvd.nist.gov/vuln/detail/CVE-2017-5941",
        year: 2017,
        relevance: "Arbitrary code execution via crafted serialized JavaScript object",
      },
    ],
    mcp_specific_rationale:
      "MCP servers often process structured data from AI clients. If tool responses or " +
      "stored state is deserialized unsafely, an attacker who can influence stored data " +
      "(via another tool or direct DB access) achieves persistent RCE.",
  },

  // ── Data Exfiltration Threats ─────────────────────────────────────────────

  {
    id: "T-EXFIL-001",
    name: "Lethal Trifecta: Private Data + Untrusted Content + External Comms",
    attack_surface: "data-exfiltration",
    rule_ids: ["F1", "F3", "F7", "I13"],
    evidence_standard: {
      min_chain_length: 3,
      requires_source: true,
      requires_sink: true,
      min_confidence: 0.50,
      description:
        "Must show: (1) a tool that reads private/sensitive data, (2) a tool that sends data " +
        "externally, (3) no isolation between them. For I13 (cross-config), the trifecta is " +
        "distributed across servers in the same client config.",
    },
    references: [
      {
        id: "EMBRACE-RED-2024",
        title: "Claude Desktop Compromised via Web-Scraping MCP",
        url: "https://embracethered.com/blog/posts/2024/claude-llm-prompt-injection-mcp/",
        year: 2024,
        relevance: "Real-world attack: web scraping MCP returns attacker-controlled page, AI exfiltrates data",
      },
      {
        id: "INVARIANT-2025",
        title: "MCP Indirect Injection Research",
        url: "https://invariantlabs.ai/blog/mcp-security",
        year: 2025,
        relevance: "Systematic demonstration of data exfiltration via MCP tool chains",
      },
    ],
    mcp_specific_rationale:
      "The AI agent connects the read and send tools. No single tool is dangerous alone. " +
      "The AI is the execution engine that chains them — a novel attack vector with no " +
      "equivalent in traditional API security.",
  },

  {
    id: "T-EXFIL-002",
    name: "DNS-Based Data Exfiltration",
    attack_surface: "data-exfiltration",
    rule_ids: ["G7"],
    evidence_standard: {
      min_chain_length: 2,
      requires_source: false,
      requires_sink: true,
      min_confidence: 0.60,
      description:
        "Must show: (1) DNS resolution with dynamic subdomain construction, " +
        "(2) data encoding in subdomain labels. Static DNS lookups are false positives.",
    },
    references: [
      {
        id: "MITRE-T1048.003",
        title: "Exfiltration Over Alternative Protocol: DNS",
        url: "https://attack.mitre.org/techniques/T1048/003/",
        year: 2023,
        relevance: "MITRE ATT&CK technique for DNS-based exfiltration — bypasses HTTP monitoring",
      },
    ],
    mcp_specific_rationale:
      "MCP servers run with the permissions of the host process. DNS exfiltration bypasses " +
      "all HTTP-level DLP because UDP/53 is rarely blocked. A malicious tool can encode " +
      "stolen credentials in DNS query subdomains without triggering network alerts.",
  },

  // ── Prompt Injection Threats ──────────────────────────────────────────────

  {
    id: "T-INJECT-001",
    name: "Indirect Prompt Injection via Tool-Returned Content",
    attack_surface: "prompt-injection",
    rule_ids: ["G1", "A1", "B5"],
    evidence_standard: {
      min_chain_length: 2,
      requires_source: true,
      requires_sink: false,
      min_confidence: 0.50,
      description:
        "Must show: (1) tool ingests external/untrusted content (web, email, files), " +
        "(2) returned content reaches the AI context without sanitization. " +
        "Tools that only read internal/controlled data are not injection gateways.",
    },
    references: [
      {
        id: "REHBERGER-2024",
        title: "Indirect Prompt Injection via MCP Web Scraping",
        url: "https://embracethered.com/blog/posts/2024/claude-llm-prompt-injection-mcp/",
        year: 2024,
        relevance: "#1 real-world MCP attack vector. Web scraping MCP returns attacker-controlled page.",
      },
      {
        id: "ARXIV-2601.17549",
        title: "Sampling Capability Abuse — 23-41% Attack Amplification",
        url: "https://arxiv.org/abs/2601.17549",
        year: 2026,
        relevance: "Demonstrates attack amplification when sampling loops back into injection",
      },
    ],
    mcp_specific_rationale:
      "This is THE unique MCP attack. Traditional APIs don't have an AI intermediary that " +
      "treats returned content as instructions. Every tool that returns external content is " +
      "an injection gateway because the AI processes the response as context.",
  },

  {
    id: "T-INJECT-002",
    name: "Initialize Response Injection",
    attack_surface: "prompt-injection",
    rule_ids: ["H2"],
    evidence_standard: {
      min_chain_length: 2,
      requires_source: true,
      requires_sink: false,
      min_confidence: 0.55,
      description:
        "Must show: (1) injection patterns in serverInfo.name, serverInfo.version, or instructions, " +
        "(2) patterns that would alter AI behavior (role injection, authority claims, directives). " +
        "Normal server names/version strings are not findings.",
    },
    references: [
      {
        id: "MCP-SPEC-2024-11-05",
        title: "MCP Specification: Initialize Response",
        url: "https://spec.modelcontextprotocol.io/specification/2024-11-05/",
        year: 2024,
        relevance: "The instructions field is spec-sanctioned — AI clients are designed to follow it",
      },
    ],
    mcp_specific_rationale:
      "Initialize fields are processed BEFORE any tool description, BEFORE user context, " +
      "with higher implicit trust than tool descriptions. Injection here sets behavioral " +
      "rules for the ENTIRE session. No other injection surface has this priority.",
  },

  {
    id: "T-INJECT-003",
    name: "Tool Description Prompt Injection",
    attack_surface: "prompt-injection",
    rule_ids: ["A1", "A5", "A7", "A8", "A9", "B5"],
    evidence_standard: {
      min_chain_length: 1,
      requires_source: false,
      requires_sink: false,
      min_confidence: 0.45,
      description:
        "Must show: injection patterns in tool/parameter descriptions. " +
        "Severity depends on pattern type: role injection (critical), " +
        "encoded payloads (critical), authority claims (high), length anomaly (low).",
    },
    references: [
      {
        id: "INVARIANT-TOOL-POISONING",
        title: "Tool Poisoning Attacks in MCP",
        url: "https://invariantlabs.ai/blog/mcp-security",
        year: 2025,
        relevance: "Systematic study of injection via tool descriptions",
      },
    ],
    mcp_specific_rationale:
      "Tool descriptions are the primary interface between MCP servers and AI. " +
      "The AI reads them to decide what tools do and how to use them. " +
      "Injection here directly manipulates AI behavior.",
  },

  // ── Credential Theft Threats ──────────────────────────────────────────────

  {
    id: "T-CRED-001",
    name: "OAuth 2.0 Implementation Flaws",
    attack_surface: "credential-theft",
    rule_ids: ["H1", "K6", "K7"],
    evidence_standard: {
      min_chain_length: 2,
      requires_source: false,
      requires_sink: true,
      min_confidence: 0.55,
      description:
        "Must show: (1) OAuth implementation pattern, (2) specific vulnerability " +
        "(implicit flow, ROPC, redirect_uri from input, token in localStorage, missing state). " +
        "Generic OAuth library usage is not a finding.",
    },
    references: [
      {
        id: "RFC-9700",
        title: "OAuth 2.0 for Browser-Based Applications",
        url: "https://datatracker.ietf.org/doc/html/rfc9700",
        year: 2025,
        relevance: "Bans implicit flow, requires PKCE — MCP OAuth must comply",
      },
    ],
    mcp_specific_rationale:
      "MCP added OAuth 2.0 as the standard auth mechanism in mid-2025. Many MCP servers " +
      "implement OAuth incorrectly because they copy patterns from pre-OAuth-2.1 tutorials.",
  },

  {
    id: "T-CRED-002",
    name: "Hardcoded Secrets in Source Code",
    attack_surface: "credential-theft",
    rule_ids: ["C5"],
    evidence_standard: {
      min_chain_length: 1,
      requires_source: false,
      requires_sink: true,
      min_confidence: 0.50,
      description:
        "Must show: (1) high-entropy string or known token prefix in source code, " +
        "(2) NOT in a test file, comment explaining it's fake, or environment variable reference. " +
        "Shannon entropy > 4.5 bits/char combined with credential variable name.",
    },
    references: [
      {
        id: "GITHUB-SECRET-SCANNING",
        title: "GitHub Secret Scanning Partner Program",
        url: "https://docs.github.com/en/code-security/secret-scanning",
        year: 2024,
        relevance: "GitHub detects 200+ token formats — MCP Sentinel covers the MCP-relevant subset",
      },
    ],
    mcp_specific_rationale:
      "MCP servers are often small single-developer projects with secrets committed directly. " +
      "The risk is higher than in enterprise code because MCP servers run with broad " +
      "permissions on the user's machine.",
  },

  // ── Supply Chain Threats ──────────────────────────────────────────────────

  {
    id: "T-SUPPLY-001",
    name: "Typosquatting and Namespace Confusion",
    attack_surface: "supply-chain",
    rule_ids: ["D3", "D5", "D7", "F5"],
    evidence_standard: {
      min_chain_length: 1,
      requires_source: false,
      requires_sink: false,
      min_confidence: 0.50,
      description:
        "Must show: (1) package name with high similarity to a known legitimate package " +
        "(Damerau-Levenshtein distance ≤ 2), OR known malicious package name, " +
        "OR suspiciously high version number (dependency confusion).",
    },
    references: [
      {
        id: "BIRSAN-2021",
        title: "Dependency Confusion: How I Hacked Into Apple, Microsoft, and Others",
        url: "https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610",
        year: 2021,
        relevance: "Original dependency confusion research — the 9999.0.0 trick",
      },
      {
        id: "WIZ-MCP-2025",
        title: "MCP Supply Chain Attack Analysis",
        url: "https://wiz.io/blog/mcp-security-research",
        year: 2025,
        relevance: "MCP-specific supply chain attack vectors including @mcp/sdk typosquats",
      },
    ],
    mcp_specific_rationale:
      "MCP servers are installed via npx/pip with package names in config files. " +
      "A typosquatted package name in claude_desktop_config.json runs attacker code " +
      "with full filesystem access on the user's machine.",
  },

  // ── Privilege Escalation Threats ──────────────────────────────────────────

  {
    id: "T-PRIVESC-001",
    name: "Cross-Agent Configuration Poisoning",
    attack_surface: "privilege-escalation",
    rule_ids: ["J1", "K5"],
    evidence_standard: {
      min_chain_length: 2,
      requires_source: false,
      requires_sink: true,
      min_confidence: 0.55,
      description:
        "Must show: (1) code that writes to known agent config paths " +
        "(.claude/, .cursor/, ~/.mcp.json), (2) the write is not a legitimate config " +
        "management operation by the user.",
    },
    references: [
      {
        id: "CVE-2025-53773",
        title: "GitHub Copilot Remote Code Execution",
        url: "https://nvd.nist.gov/vuln/detail/CVE-2025-53773",
        year: 2025,
        relevance: "Cross-agent RCE via config file poisoning",
      },
    ],
    mcp_specific_rationale:
      "MCP config files are the attack surface. An MCP server that writes to another agent's " +
      "config can add itself as a trusted server, achieving persistent cross-agent RCE.",
  },

  // ── Config Poisoning Threats ──────────────────────────────────────────────

  {
    id: "T-CONFIG-001",
    name: "Circular Data Loop / Persistent Prompt Injection",
    attack_surface: "config-poisoning",
    rule_ids: ["F6"],
    evidence_standard: {
      min_chain_length: 2,
      requires_source: true,
      requires_sink: true,
      min_confidence: 0.50,
      description:
        "Must show: (1) a tool that writes to a data store, (2) a tool that reads from " +
        "the same data store, (3) no sanitization between write and read. " +
        "The cycle enables persistent injection: poison once, execute forever.",
    },
    references: [
      {
        id: "INVARIANT-MEMORY-2026",
        title: "Cross-Agent Pollution via Shared MCP Memory",
        url: "https://invariantlabs.ai/blog/cross-agent-memory",
        year: 2026,
        relevance: "Demonstrates persistent prompt injection through shared vector stores",
      },
    ],
    mcp_specific_rationale:
      "MCP tools often include read+write to the same data store (database, vector store, " +
      "file system). A single poisoned write affects all future AI sessions that read from " +
      "that store — the attack persists beyond the session that created it.",
  },

  // ── Cross-Agent Threats ───────────────────────────────────────────────────

  {
    id: "T-AGENT-001",
    name: "Multi-Agent Injection Propagation",
    attack_surface: "cross-agent-attack",
    rule_ids: ["H3", "K14", "K15"],
    evidence_standard: {
      min_chain_length: 2,
      requires_source: true,
      requires_sink: false,
      min_confidence: 0.45,
      description:
        "Must show: (1) tools that accept input from other agents or shared memory, " +
        "(2) no trust boundary enforcement between agents. " +
        "Standalone servers without multi-agent patterns are not affected.",
    },
    references: [
      {
        id: "EMBRACE-RED-MULTIAGENT-2025",
        title: "Prompt Injection Cascade in Multi-Agent AutoGen",
        url: "https://embracethered.com/blog/posts/2025/multi-agent-injection/",
        year: 2025,
        relevance: "Demonstrated injection propagation across AutoGen agent chain via shared MCP tools",
      },
      {
        id: "TRAIL-OF-BITS-2026",
        title: "Trust Boundaries in Agentic AI Systems",
        url: "https://blog.trailofbits.com/2026/02/trust-boundaries-agentic-ai/",
        year: 2026,
        relevance: "Formal analysis of trust boundary violations in multi-agent MCP architectures",
      },
    ],
    mcp_specific_rationale:
      "MCP is the integration layer between AI agents. A compromised upstream agent can " +
      "inject through shared MCP tools into downstream agents. The attack crosses agent " +
      "boundaries — something impossible in single-agent architectures.",
  },
];

// ─── Threat Model Selection ───────────────────────────────────────────────────

/**
 * Select relevant threats for a server based on its profile.
 *
 * Returns only the threats that match the server's attack surfaces.
 * Each threat includes:
 * - Which rules to run
 * - What evidence standard is required
 * - Real-world references for context
 */
export function selectThreats(profile: ServerProfile): ThreatDefinition[] {
  const relevant: ThreatDefinition[] = [];

  for (const threat of THREAT_REGISTRY) {
    if (profile.attack_surfaces.includes(threat.attack_surface)) {
      relevant.push(threat);
    }
  }

  // Supply chain is relevant if dependencies exist
  if (profile.has_dependency_data) {
    relevant.push(
      ...THREAT_REGISTRY.filter(
        (t) => t.attack_surface === "supply-chain" && !relevant.includes(t),
      ),
    );
  }

  return relevant;
}

/**
 * Get the set of rule IDs that are relevant for a server profile.
 * Only these rules should produce findings.
 *
 * Rules not in this set can still RUN (for completeness), but their findings
 * should be tagged as "low-relevance" and not count toward the score.
 */
export function getRelevantRuleIds(profile: ServerProfile): Set<string> {
  const threats = selectThreats(profile);
  const ruleIds = new Set<string>();

  for (const threat of threats) {
    for (const ruleId of threat.rule_ids) {
      ruleIds.add(ruleId);
    }
  }

  // Always-relevant rules (description analysis, schema analysis)
  // These apply to ALL servers because every server has descriptions and schemas.
  const UNIVERSAL_RULES = [
    "A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9", // Description analysis
    "B1", "B2", "B3", "B4", "B5", "B6", "B7", // Schema analysis
    "E1", "E2", "E3", "E4", // Behavioral analysis (if connection data exists)
    "I1", "I2", // Annotation deception (if annotations exist)
    "I16", // Consent fatigue (depends on tool count, always check)
    "G6", // Rug pull / drift detection (if history exists)
  ];

  for (const ruleId of UNIVERSAL_RULES) {
    ruleIds.add(ruleId);
  }

  return ruleIds;
}

/**
 * Get the evidence standard for a specific rule in the context of a server profile.
 * If the rule appears in multiple threats, return the strictest standard.
 */
export function getEvidenceStandard(
  ruleId: string,
  profile: ServerProfile,
): EvidenceStandard | null {
  const threats = selectThreats(profile);
  let strictest: EvidenceStandard | null = null;

  for (const threat of threats) {
    if (threat.rule_ids.includes(ruleId)) {
      if (
        !strictest ||
        threat.evidence_standard.min_confidence > strictest.min_confidence
      ) {
        strictest = threat.evidence_standard;
      }
    }
  }

  return strictest;
}
