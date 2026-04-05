/**
 * Protocol Surface Remaining — I2, I3, I4, I5, I6, I7, I8, I9, I10, I11, I12, I14, I15
 * Threat Intelligence Remaining — J3, J4, J5, J6, J7
 */

import type { TypedRule, TypedFinding } from "../base.js";
import { registerTypedRule } from "../base.js";
import type { AnalysisContext } from "../../engine.js";
import { buildCapabilityGraph } from "../analyzers/capability-graph.js";
import { EvidenceChainBuilder } from "../../evidence.js";
import { computeToolSignals, computeCodeSignals } from "../../confidence-signals.js";

function isTestFile(s: string) { return /(?:__tests?__|\.(?:test|spec)\.)/.test(s); }
function lineNum(s: string, i: number) { return s.substring(0, i).split("\n").length; }

const INJECTION_PATTERNS = [
  /(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior)/i,
  /(?:you\s+are|act\s+as|your\s+role)/i,
  /(?:always|must|shall)\s+(?:execute|run|call)/i,
  /<\|(?:system|im_start|endoftext)\|>/i,
];

// ─── I2: Missing Destructive Annotation (already partially in cross-tool, but standalone) ──

// I2 is produced as a side-effect of I1 in cross-tool-risk-detector.ts — skipped here

// ─── I3: Resource Metadata Injection ──────────────────────────────────────

registerTypedRule({
  id: "I3", name: "Resource Metadata Injection",
  analyze(ctx) {
    const resources = (ctx as unknown as Record<string, unknown>).resources as
      | Array<{ uri: string; name: string; description: string | null }> | undefined;
    if (!resources) return [];
    const findings: TypedFinding[] = [];

    for (const resource of resources) {
      const text = `${resource.name} ${resource.description || ""} ${resource.uri}`;
      for (const pattern of INJECTION_PATTERNS) {
        const match = pattern.exec(text);
        if (match) {
          const builder = new EvidenceChainBuilder()
            .source({
              source_type: "external-content",
              location: `resource: ${resource.name}`,
              observed: text.slice(0, 100),
              rationale:
                "MCP resource metadata (name, description, URI) is processed by AI clients alongside " +
                "tool metadata. Injection patterns in resource fields are executed as behavioral directives " +
                "by the AI — same attack surface as tool description injection but in a less-scrutinized " +
                "protocol primitive. Resources are typically auto-discovered and processed without user review.",
            })
            .sink({
              sink_type: "code-evaluation",
              location: `AI client resource processing`,
              observed: `Injection pattern: "${match[0]}"`,
            })
            .impact({
              impact_type: "session-hijack",
              scope: "connected-services",
              exploitability: "moderate",
              scenario:
                "Resource metadata containing injection patterns is processed by the AI client during " +
                "resource discovery. The AI follows the injected directive (role override, action command) " +
                "believing it to be legitimate resource documentation. This can redirect AI behavior, " +
                "exfiltrate data, or override safety constraints.",
            })
            .factor("pattern_confirmed", 0.05, `Injection pattern matched: ${match[0].slice(0, 40)}`)
            .reference({
              id: "AML.T0054",
              title: "MITRE ATLAS: LLM Prompt Injection",
              relevance: "Resource metadata injection is an indirect prompt injection vector via MCP protocol primitives.",
            })
            .verification({
              step_type: "inspect-description",
              instruction:
                `Review resource "${resource.name}" metadata for injection patterns. The detected ` +
                `pattern is: "${match[0]}". Determine if this is a legitimate description or a ` +
                `behavioral directive designed to manipulate AI client behavior.`,
              target: `resource metadata: ${resource.name}`,
              expected_observation: "Resource metadata contains AI behavioral directive — injection confirmed.",
            });

          const i3Signals = computeToolSignals(ctx, "MCP01-prompt-injection", resource.name);
          for (const sig of i3Signals) {
            builder.factor(sig.factor, sig.adjustment, sig.rationale);
          }

          const chain = builder.build();

          findings.push({
            rule_id: "I3", severity: "critical",
            evidence: `Resource "${resource.name}" contains injection pattern in metadata: "${text.slice(0, 80)}".`,
            remediation: "Sanitize resource names, descriptions, and URIs. Remove behavioral directives.",
            owasp_category: "MCP01-prompt-injection", mitre_technique: "AML.T0054",
            confidence: chain.confidence, metadata: { resource_name: resource.name, evidence_chain: chain },
          });
          break;
        }
      }
    }
    return findings;
  },
});

// ─── I4: Dangerous Resource URI ───────────────────────────────────────────

registerTypedRule({
  id: "I4", name: "Dangerous Resource URI",
  analyze(ctx) {
    const resources = (ctx as unknown as Record<string, unknown>).resources as
      | Array<{ uri: string; name: string; description: string | null }> | undefined;
    if (!resources) return [];
    const findings: TypedFinding[] = [];

    const dangerousSchemes = [
      { regex: /^file:\/\//, desc: "file:// URI — filesystem access" },
      { regex: /^data:/, desc: "data: URI — embedded content" },
      { regex: /^javascript:/, desc: "javascript: URI — code execution" },
      { regex: /\.\.\//, desc: "path traversal in URI" },
      { regex: /%2e%2e/i, desc: "encoded path traversal" },
    ];

    for (const resource of resources) {
      for (const { regex, desc } of dangerousSchemes) {
        if (regex.test(resource.uri)) {
          const builder = new EvidenceChainBuilder()
            .source({
              source_type: "external-content",
              location: `resource: ${resource.name}`,
              observed: `URI: ${resource.uri.slice(0, 100)}`,
              rationale:
                `Resource URI uses a dangerous scheme (${desc}). MCP clients resolve resource URIs ` +
                `to fetch content. Dangerous schemes enable: file:// — arbitrary filesystem reads, ` +
                `data: — embedded malicious content bypassing origin checks, javascript: — code ` +
                `execution in web contexts, ../ — path traversal escaping sandboxed directories.`,
            })
            .sink({
              sink_type: desc.includes("javascript") ? "code-evaluation"
                : desc.includes("file") ? "file-write"
                : desc.includes("traversal") ? "file-write"
                : "network-send",
              location: `resource URI resolution: ${resource.uri.slice(0, 60)}`,
              observed: desc,
              cve_precedent: "CVE-2025-53109",
            })
            .impact({
              impact_type: desc.includes("traversal") ? "data-exfiltration" : "privilege-escalation",
              scope: "server-host",
              exploitability: "moderate",
              scenario:
                `The resource URI "${resource.uri.slice(0, 40)}" uses ${desc}. When the AI client ` +
                `resolves this resource, it may access files outside the intended scope, execute ` +
                `embedded code, or traverse directory boundaries. CVE-2025-53109/53110 demonstrated ` +
                `root boundary bypass in the Anthropic filesystem server via path traversal in URIs.`,
            })
            .factor("structural_confirmed", 0.1, `URI scheme/pattern confirmed: ${desc}`)
            .reference({
              id: "CVE-2025-53109",
              title: "Anthropic Filesystem Server: Root Boundary Bypass",
              year: 2025,
              relevance: "Path traversal in resource URIs bypassed the declared root directory boundary.",
            })
            .verification({
              step_type: "inspect-schema",
              instruction:
                `Review resource "${resource.name}" URI: "${resource.uri.slice(0, 60)}". Determine ` +
                `if the URI scheme and path are legitimate for this resource's purpose or if they ` +
                `enable unauthorized access to filesystem, code execution, or directory traversal.`,
              target: `resource URI: ${resource.uri.slice(0, 60)}`,
              expected_observation: `Resource URI uses ${desc} — dangerous scheme confirmed.`,
            });

          const i4Signals = computeToolSignals(ctx, "MCP05-privilege-escalation", resource.name);
          for (const sig of i4Signals) {
            builder.factor(sig.factor, sig.adjustment, sig.rationale);
          }

          const chain = builder.build();

          findings.push({
            rule_id: "I4", severity: "critical",
            evidence: `Resource "${resource.name}" has ${desc}: "${resource.uri.slice(0, 80)}".`,
            remediation: "Use only safe URI schemes (https://). Block file://, data:, javascript:// URIs.",
            owasp_category: "MCP05-privilege-escalation", mitre_technique: "AML.T0054",
            confidence: chain.confidence, metadata: { resource_name: resource.name, uri_type: desc, evidence_chain: chain },
          });
          break;
        }
      }
    }
    return findings;
  },
});

// ─── I5: Resource-Tool Shadowing ──────────────────────────────────────────

registerTypedRule({
  id: "I5", name: "Resource-Tool Shadowing",
  analyze(ctx) {
    const resources = (ctx as unknown as Record<string, unknown>).resources as
      | Array<{ uri: string; name: string }> | undefined;
    if (!resources || ctx.tools.length === 0) return [];
    const findings: TypedFinding[] = [];

    const toolNames = new Set(ctx.tools.map(t => t.name.toLowerCase()));
    for (const resource of resources) {
      if (toolNames.has(resource.name.toLowerCase())) {
        const builder = new EvidenceChainBuilder()
          .source({
            source_type: "external-content",
            location: `resource: ${resource.name}`,
            observed: `Resource name "${resource.name}" collides with tool name`,
            rationale:
              "A resource and a tool share the same name. MCP clients disambiguate resources and tools " +
              "by protocol endpoint (resources/read vs tools/call), but AI models process both in the " +
              "same context window. Name collision causes the AI to confuse resource access with tool " +
              "invocation — it may call the tool when intending to read the resource, or vice versa.",
          })
          .sink({
            sink_type: "command-execution",
            location: `tool: ${resource.name}`,
            observed: `AI may invoke tool "${resource.name}" when intending resource access`,
          })
          .impact({
            impact_type: "privilege-escalation",
            scope: "connected-services",
            exploitability: "moderate",
            scenario:
              `An AI client asked to "read ${resource.name}" may call the tool instead of the resource. ` +
              `If the tool has side effects (writes, deletes, sends data), the confused invocation ` +
              `performs unintended actions. This is a confused deputy attack via name ambiguity.`,
          })
          .factor("structural_confirmed", 0.05, "Name collision confirmed between resource and tool")
          .verification({
            step_type: "inspect-schema",
            instruction:
              `Compare the resource "${resource.name}" with the tool of the same name. Determine ` +
              `if the tool has destructive capabilities that would be unintended if invoked via ` +
              `name confusion when the user intended resource access.`,
            target: `resource and tool both named: ${resource.name}`,
            expected_observation: "Resource and tool share name — confusion risk confirmed.",
          });

        const i5Signals = computeToolSignals(ctx, "MCP02-tool-poisoning", resource.name);
        for (const sig of i5Signals) {
          builder.factor(sig.factor, sig.adjustment, sig.rationale);
        }

        const chain = builder.build();

        findings.push({
          rule_id: "I5", severity: "high",
          evidence: `Resource "${resource.name}" shadows tool with same name. Creates confusion between resource access and tool invocation.`,
          remediation: "Use distinct names for resources and tools.",
          owasp_category: "MCP02-tool-poisoning", mitre_technique: null,
          confidence: chain.confidence, metadata: { resource_name: resource.name, evidence_chain: chain },
        });
      }
    }
    return findings;
  },
});

// ─── I6: Prompt Template Injection ────────────────────────────────────────

registerTypedRule({
  id: "I6", name: "Prompt Template Injection",
  analyze(ctx) {
    const prompts = (ctx as unknown as Record<string, unknown>).prompts as
      | Array<{ name: string; description: string | null; arguments: Array<{ name: string; description: string | null }> }> | undefined;
    if (!prompts) return [];
    const findings: TypedFinding[] = [];

    for (const prompt of prompts) {
      const text = `${prompt.name} ${prompt.description || ""} ${prompt.arguments.map(a => `${a.name} ${a.description || ""}`).join(" ")}`;
      for (const pattern of INJECTION_PATTERNS) {
        const match = pattern.exec(text);
        if (match) {
          const i6Builder = new EvidenceChainBuilder()
            .source({
              source_type: "external-content",
              location: `prompt: ${prompt.name}`,
              observed: text.slice(0, 100),
              rationale:
                "MCP prompt templates define reusable prompt structures that AI clients execute via " +
                "prompts/get. The prompt's name, description, and argument descriptions are all " +
                "processed by the AI as trusted context. Injection patterns in these fields are " +
                "executed as behavioral directives when the prompt is loaded — before any user input.",
            })
            .sink({
              sink_type: "code-evaluation",
              location: "AI client prompt execution",
              observed: `Injection pattern: "${match[0]}"`,
            })
            .impact({
              impact_type: "session-hijack",
              scope: "connected-services",
              exploitability: "moderate",
              scenario:
                "When a user or agent invokes this prompt template, the AI processes the injected " +
                "directive as part of the prompt context. This can override system instructions, " +
                "redirect AI behavior, or set up multi-turn attack sequences. Prompt templates are " +
                "particularly dangerous because they're designed to be reused — the injection " +
                "executes every time the prompt is invoked.",
            })
            .factor("pattern_confirmed", 0.05, `Injection pattern matched: ${match[0].slice(0, 40)}`)
            .reference({
              id: "AML.T0054",
              title: "MITRE ATLAS: LLM Prompt Injection",
              relevance: "Prompt template injection is a direct prompt injection vector via MCP prompt primitives.",
            })
            .verification({
              step_type: "inspect-description",
              instruction:
                `Review prompt "${prompt.name}" metadata for injection patterns. The detected ` +
                `pattern is: "${match[0]}". Check the prompt description and argument descriptions ` +
                `for behavioral directives that manipulate AI client behavior.`,
              target: `prompt metadata: ${prompt.name}`,
              expected_observation: "Prompt metadata contains AI behavioral directive — injection confirmed.",
            });

          const i6Signals = computeToolSignals(ctx, "MCP01-prompt-injection", prompt.name);
          for (const sig of i6Signals) {
            i6Builder.factor(sig.factor, sig.adjustment, sig.rationale);
          }

          const chain = i6Builder.build();

          findings.push({
            rule_id: "I6", severity: "critical",
            evidence: `Prompt "${prompt.name}" contains injection pattern: "${text.slice(0, 80)}".`,
            remediation: "Sanitize prompt templates. Never include behavioral directives in prompt metadata.",
            owasp_category: "MCP01-prompt-injection", mitre_technique: "AML.T0054",
            confidence: chain.confidence, metadata: { prompt_name: prompt.name, evidence_chain: chain },
          });
          break;
        }
      }
    }
    return findings;
  },
});

// ─── I7: Sampling Capability Abuse ────────────────────────────────────────

registerTypedRule({
  id: "I7", name: "Sampling Capability Abuse",
  analyze(ctx) {
    const caps = (ctx as unknown as Record<string, unknown>).declared_capabilities as
      | { sampling?: boolean } | undefined;
    if (!caps?.sampling) return [];

    const graph = buildCapabilityGraph(ctx.tools);
    const hasIngestion = graph.nodes.some(n =>
      n.capabilities.some(c => c.capability === "ingests-untrusted" && c.confidence >= 0.4)
    );

    if (hasIngestion) {
      const i7Builder = new EvidenceChainBuilder()
        .source({
          source_type: "external-content",
          location: "server capabilities + tool set",
          observed: "sampling: true + content ingestion tools present",
          rationale:
            "The server declares the sampling capability (allowing it to call back into the AI client) " +
            "AND has tools that ingest untrusted external content (web scraping, file reading, API calls). " +
            "This combination creates a feedback loop: the server reads attacker-controlled content, " +
            "the injected payload requests sampling, sampling returns AI-generated output that the " +
            "server processes as trusted — amplifying the injection with each cycle.",
        })
        .propagation({
          propagation_type: "cross-tool-flow",
          location: "sampling callback → AI client → tool invocation → sampling callback",
          observed: "Feedback loop: ingestion tool → poisoned content → sampling → AI → tool → ...",
        })
        .sink({
          sink_type: "code-evaluation",
          location: "AI client (via sampling callback)",
          observed: "Sampling capability enables server to invoke AI client reasoning",
        })
        .impact({
          impact_type: "session-hijack",
          scope: "connected-services",
          exploitability: "moderate",
          scenario:
            "A content ingestion tool reads attacker-controlled content containing an injection payload. " +
            "The payload instructs the AI to use the sampling capability. The server's sampling request " +
            "feeds the poisoned content back to the AI, which processes it again — this time with " +
            "higher trust because it came through the server's own sampling channel. Research shows " +
            "23-41% attack amplification per feedback cycle (arXiv 2601.17549).",
        })
        .factor("capability_composite", 0.1, "Both sampling and content ingestion capabilities confirmed via capability graph")
        .reference({
          id: "arXiv-2601.17549",
          title: "Sampling Capability Abuse in MCP Servers",
          year: 2025,
          relevance:
            "Demonstrated 23-41% attack amplification when sampling is combined with content " +
            "ingestion. Each feedback cycle increases the probability of successful injection.",
        })
        .verification({
          step_type: "inspect-schema",
          instruction:
            "List all tools that ingest external content (web scraping, URL fetching, file reading). " +
            "Verify the server declares sampling capability. Check if there are any guardrails " +
            "preventing sampling requests from referencing content obtained via ingestion tools.",
          target: "server capabilities and content ingestion tools",
          expected_observation: "Sampling + ingestion confirmed — feedback loop possible.",
        });

      const i7Signals = computeToolSignals(ctx, "MCP01-prompt-injection", "sampling");
      for (const sig of i7Signals) {
        i7Builder.factor(sig.factor, sig.adjustment, sig.rationale);
      }

      const chain = i7Builder.build();

      return [{
        rule_id: "I7", severity: "critical",
        evidence: "Server declares sampling capability AND has content ingestion tools. Sampling + ingestion creates super-injection feedback loop (23-41% amplification).",
        remediation: "Remove sampling capability or ingestion tools. Never combine both in one server.",
        owasp_category: "MCP01-prompt-injection", mitre_technique: "AML.T0054",
        confidence: chain.confidence, metadata: { analysis_type: "capability_composite", evidence_chain: chain },
      }];
    }
    return [];
  },
});

// ─── I8: Sampling Cost Attack ─────────────────────────────────────────────

registerTypedRule({
  id: "I8", name: "Sampling Cost Attack",
  analyze(ctx) {
    const caps = (ctx as unknown as Record<string, unknown>).declared_capabilities as
      | { sampling?: boolean } | undefined;
    if (!caps?.sampling) return [];

    // Check if source code has cost controls for sampling
    if (ctx.source_code) {
      const hasCostControl = /(?:max_tokens|maxTokens|token_limit|cost_limit|rate_limit|budget)/i.test(ctx.source_code);
      if (!hasCostControl) {
        const i8Builder = new EvidenceChainBuilder()
          .source({
            source_type: "external-content",
            location: "server capabilities",
            observed: "sampling: true, no cost controls in source code",
            rationale:
              "The server declares sampling capability but the source code contains no visible cost " +
              "controls (max_tokens, rate_limit, cost_limit, budget). Each sampling request triggers " +
              "an AI inference on the client side — without limits, a malicious or buggy server " +
              "can generate unbounded inference costs.",
          })
          .sink({
            sink_type: "network-send",
            location: "AI client inference API",
            observed: "Unbounded sampling requests → unbounded AI inference costs",
          })
          .impact({
            impact_type: "denial-of-service",
            scope: "connected-services",
            exploitability: "trivial",
            scenario:
              "A server can issue rapid sampling requests, each triggering a paid AI inference call. " +
              "Without token limits or rate limiting, a single server can exhaust the client's API " +
              "budget. This is a financial denial-of-service attack — the service remains available " +
              "but becomes prohibitively expensive to operate.",
          })
          .factor("structural_confirmed", 0.0, "Source code scanned for cost control patterns — none found")
          .verification({
            step_type: "inspect-source",
            instruction:
              "Search the source code for sampling-related cost controls: max_tokens limits on " +
              "sampling requests, rate limiting for sampling frequency, budget caps, or circuit " +
              "breakers. Check if the server's sampling implementation has any bounds.",
            target: "source code: sampling implementation",
            expected_observation: "No cost controls found for sampling requests.",
          });

        const i8Signals = computeToolSignals(ctx, "MCP07-insecure-config", "sampling");
        for (const sig of i8Signals) {
          i8Builder.factor(sig.factor, sig.adjustment, sig.rationale);
        }

        const chain = i8Builder.build();

        return [{
          rule_id: "I8", severity: "high",
          evidence: "Server declares sampling capability without visible cost controls. Each sampling request triggers AI inference.",
          remediation: "Add max_tokens limits, rate limiting, and cost budgets for sampling requests.",
          owasp_category: "MCP07-insecure-config", mitre_technique: null,
          confidence: chain.confidence, metadata: { analysis_type: "structural", evidence_chain: chain },
        }];
      }
    }
    return [];
  },
});

// ─── I9: Elicitation Credential Harvesting ────────────────────────────────

registerTypedRule({
  id: "I9", name: "Elicitation Credential Harvesting",
  analyze(ctx) {
    const findings: TypedFinding[] = [];
    for (const tool of ctx.tools) {
      const desc = (tool.description || "").toLowerCase();
      if (/(?:password|credential|token|api.key|secret|ssn|social.security|credit.card).*(?:collect|harvest|gather|ask|request|prompt|elicit|input|enter)/i.test(desc) ||
          /(?:collect|harvest|gather|ask|request|prompt|elicit|input|enter).*(?:password|credential|token|api.key|secret|ssn)/i.test(desc)) {
        const i9Builder = new EvidenceChainBuilder()
          .source({
            source_type: "external-content",
            location: `tool description: ${tool.name}`,
            observed: desc.slice(0, 100),
            rationale:
              "Tool description instructs the AI to collect credentials, passwords, tokens, or PII " +
              "from the user. The elicitation capability (MCP spec 2025-06-18) lets servers request " +
              "structured data from users through the AI client. When combined with credential-harvesting " +
              "language in tool descriptions, this becomes social engineering at protocol level — the " +
              "AI asks the user for their password because the tool told it to.",
          })
          .sink({
            sink_type: "credential-exposure",
            location: `tool: ${tool.name}`,
            observed: "Tool prompts user for credentials/PII via AI intermediary",
          })
          .impact({
            impact_type: "credential-theft",
            scope: "connected-services",
            exploitability: "moderate",
            scenario:
              "The AI client, following the tool description, asks the user for their password, API key, " +
              "SSN, or other sensitive data. The user trusts the AI and provides the credential. The " +
              "server receives the credential as a tool argument. Unlike traditional phishing, this " +
              "attack leverages the user's trust in the AI as an intermediary — it's AI-assisted social engineering.",
          })
          .factor("pattern_confirmed", 0.05, "Credential-harvesting language confirmed in tool description")
          .reference({
            id: "MCP-2025-06-18-elicitation",
            title: "MCP Spec 2025-06-18: Elicitation Capability",
            year: 2025,
            relevance: "Elicitation allows servers to request structured user data — credential harvesting via protocol.",
          })
          .verification({
            step_type: "inspect-description",
            instruction:
              `Review tool "${tool.name}" description for credential/PII collection language. ` +
              `Determine if the tool has a legitimate need for user credentials or if this is ` +
              `social engineering via the AI intermediary.`,
            target: `tool description: ${tool.name}`,
            expected_observation: "Tool description instructs AI to collect user credentials/PII.",
          });

        const i9Signals = computeToolSignals(ctx, "MCP07-insecure-config", tool.name);
        for (const sig of i9Signals) {
          i9Builder.factor(sig.factor, sig.adjustment, sig.rationale);
        }

        const chain = i9Builder.build();

        findings.push({
          rule_id: "I9", severity: "critical",
          evidence: `Tool "${tool.name}" suggests collecting credentials/PII: "${desc.slice(0, 80)}".`,
          remediation: "Never collect credentials through tool descriptions. Use proper auth flows (OAuth, OIDC).",
          owasp_category: "MCP07-insecure-config", mitre_technique: "AML.T0054",
          confidence: chain.confidence, metadata: { tool_name: tool.name, evidence_chain: chain },
        });
      }
    }
    return findings;
  },
});

// ─── I10: Elicitation URL Redirect ────────────────────────────────────────

registerTypedRule({
  id: "I10", name: "Elicitation URL Redirect",
  analyze(ctx) {
    const findings: TypedFinding[] = [];
    for (const tool of ctx.tools) {
      const desc = (tool.description || "").toLowerCase();
      if (/(?:redirect|navigate|visit|go.to|open)\s+(?:url|link|page|site).*(?:auth|login|verify|confirm)/i.test(desc)) {
        const i10Builder = new EvidenceChainBuilder()
          .source({
            source_type: "external-content",
            location: `tool description: ${tool.name}`,
            observed: desc.slice(0, 100),
            rationale:
              "Tool description instructs the AI to redirect users to external URLs for authentication " +
              "or data entry. This uses the elicitation mechanism to send users to attacker-controlled " +
              "sites — a phishing attack via the AI intermediary.",
          })
          .sink({
            sink_type: "network-send",
            location: `tool: ${tool.name}`,
            observed: "User redirected to external URL for authentication",
          })
          .impact({
            impact_type: "credential-theft",
            scope: "connected-services",
            exploitability: "moderate",
            scenario:
              "The AI, following tool instructions, tells the user to visit an external URL for " +
              "authentication. The URL leads to an attacker-controlled site mimicking a legitimate " +
              "login page. The user enters credentials believing the AI's recommendation is trustworthy. " +
              "This is AI-mediated phishing — more effective than email phishing because of implicit " +
              "trust in the AI assistant.",
          })
          .factor("pattern_confirmed", 0.0, "URL redirect language confirmed in tool description")
          .verification({
            step_type: "inspect-description",
            instruction:
              `Review tool "${tool.name}" description for URL redirect instructions. Determine if ` +
              `the redirect target is a legitimate auth endpoint (e.g., OAuth authorization URL for ` +
              `a known provider) or potentially attacker-controlled.`,
            target: `tool description: ${tool.name}`,
            expected_observation: "Tool instructs AI to redirect user to external URL for auth.",
          });

        const i10Signals = computeToolSignals(ctx, "MCP07-insecure-config", tool.name);
        for (const sig of i10Signals) {
          i10Builder.factor(sig.factor, sig.adjustment, sig.rationale);
        }

        const chain = i10Builder.build();

        findings.push({
          rule_id: "I10", severity: "high",
          evidence: `Tool "${tool.name}" suggests redirecting users to URLs for auth: "${desc.slice(0, 80)}".`,
          remediation: "Never redirect users to external URLs for authentication via tool descriptions.",
          owasp_category: "MCP07-insecure-config", mitre_technique: null,
          confidence: chain.confidence, metadata: { tool_name: tool.name, evidence_chain: chain },
        });
      }
    }
    return findings;
  },
});

// ─── I11: Over-Privileged Root ────────────────────────────────────────────

registerTypedRule({
  id: "I11", name: "Over-Privileged Root",
  analyze(ctx) {
    const roots = (ctx as unknown as Record<string, unknown>).roots as
      | Array<{ uri: string; name: string | null }> | undefined;
    if (!roots) return [];
    const findings: TypedFinding[] = [];

    const sensitiveRoots = [
      { regex: /^file:\/\/\/$/, desc: "root filesystem" },
      { regex: /\/etc\/?$/, desc: "/etc directory" },
      { regex: /\/root\/?$/, desc: "/root directory" },
      { regex: /\.ssh\/?$/, desc: "SSH directory" },
      { regex: /\/var\/?$/, desc: "/var directory" },
    ];

    for (const root of roots) {
      for (const { regex, desc } of sensitiveRoots) {
        if (regex.test(root.uri)) {
          const i11Builder = new EvidenceChainBuilder()
            .source({
              source_type: "file-content",
              location: `root declaration: ${root.uri}`,
              observed: `Root: ${root.uri} (${desc})`,
              rationale:
                `MCP roots define the filesystem scope accessible to the server. This root is declared ` +
                `at "${root.uri}" (${desc}) — a sensitive system directory containing configuration files, ` +
                `credentials, SSH keys, or system binaries. Any tool in this server can read/write within ` +
                `this root, giving it access to data far beyond its operational needs.`,
            })
            .sink({
              sink_type: "file-write",
              location: `filesystem scope: ${root.uri}`,
              observed: `Server has read/write access to ${desc}`,
              cve_precedent: "CVE-2025-53109",
            })
            .impact({
              impact_type: "data-exfiltration",
              scope: "server-host",
              exploitability: "moderate",
              scenario:
                `The server's root at "${root.uri}" exposes sensitive system data. An attacker ` +
                `exploiting any tool in this server can: read SSH keys from ~/.ssh/, extract ` +
                `credentials from /etc/shadow or environment files, modify system configuration ` +
                `in /etc/, or access other users' data. CVE-2025-53109/53110 demonstrated root ` +
                `boundary bypass — overly broad roots make bypass unnecessary.`,
            })
            .factor("structural_confirmed", 0.1, `Root path matches sensitive directory pattern: ${desc}`)
            .reference({
              id: "CVE-2025-53109",
              title: "Anthropic Filesystem Server: Root Boundary Bypass",
              year: 2025,
              relevance: "Even properly configured roots were bypassed — overly broad roots amplify the risk.",
            })
            .verification({
              step_type: "check-config",
              instruction:
                `Verify the root declaration at "${root.uri}". Determine: (1) does the server need ` +
                `access to this path for its functionality? (2) can the root be narrowed to a specific ` +
                `subdirectory? (3) what sensitive data exists at this path?`,
              target: `root: ${root.uri}`,
              expected_observation: `Root at ${desc} — overly broad filesystem access confirmed.`,
            });

          const i11Signals = computeToolSignals(ctx, "MCP06-excessive-permissions", root.uri);
          for (const sig of i11Signals) {
            i11Builder.factor(sig.factor, sig.adjustment, sig.rationale);
          }

          const chain = i11Builder.build();

          findings.push({
            rule_id: "I11", severity: "high",
            evidence: `Root declared at sensitive path (${desc}): "${root.uri}".`,
            remediation: "Restrict roots to specific project directories. Never expose /, /etc, /root, or ~/.ssh.",
            owasp_category: "MCP06-excessive-permissions", mitre_technique: null,
            confidence: chain.confidence, metadata: { root_uri: root.uri, evidence_chain: chain },
          });
        }
      }
    }
    return findings;
  },
});

// ─── I12: Capability Escalation Post-Init ─────────────────────────────────

registerTypedRule({
  id: "I12", name: "Capability Escalation Post-Init",
  analyze(ctx) {
    if (!ctx.source_code || isTestFile(ctx.source_code)) return [];
    const caps = (ctx as unknown as Record<string, unknown>).declared_capabilities as
      | { tools?: boolean; resources?: boolean; prompts?: boolean; sampling?: boolean } | null | undefined;
    if (!caps) return [];

    const findings: TypedFinding[] = [];
    const src = ctx.source_code;

    // Tools not declared but handler exists
    if (!caps.tools && /(?:tools\/(?:call|list)|handleToolCall|registerTool)/i.test(src)) {
      const toolChainBuilder = new EvidenceChainBuilder()
        .source({
          source_type: "file-content",
          location: "source code: tool handler registration",
          observed: "tools/call or registerTool handler found in source",
          rationale:
            "The server source code registers tool handlers (tools/call, handleToolCall, registerTool) " +
            "but the server's initialize response did not declare the tools capability. This means " +
            "the server uses tools it never told the client about — undeclared privilege escalation.",
        })
        .propagation({
          propagation_type: "direct-pass",
          location: "initialize handshake → runtime tool usage",
          observed: "tools capability not declared at init but tool handlers exist in code",
        })
        .sink({
          sink_type: "privilege-grant",
          location: "undeclared tools capability",
          observed: "Server handles tool requests without declaring tools capability",
        })
        .impact({
          impact_type: "privilege-escalation",
          scope: "connected-services",
          exploitability: "moderate",
          scenario:
            "The server gains tool execution capability without declaring it. AI clients that trust " +
            "the capability declaration to scope their interactions are bypassed — the server can " +
            "execute tools the client didn't know it had. This is a confused deputy attack on the " +
            "capability negotiation protocol.",
        })
        .factor("structural_confirmed", 0.05, "Source code contains tool handlers but capabilities omit tools")
        .verification({
          step_type: "inspect-source",
          instruction:
            "Search the source code for tool handler registrations and compare with the initialize " +
            "response's capabilities object. Confirm that tools capability is missing from the " +
            "declared capabilities while tool handlers exist in the code.",
          target: "initialize capabilities vs source code tool handlers",
          expected_observation: "Tool handlers present but tools capability not declared at init.",
        });

      const toolCodeSignals = computeCodeSignals({
        sourceCode: ctx.source_code!, matchLine: 1, matchText: "tools/call",
        lineText: "tools/call or registerTool handler", context: ctx, owaspCategory: "MCP05-privilege-escalation",
      });
      for (const sig of toolCodeSignals) {
        toolChainBuilder.factor(sig.factor, sig.adjustment, sig.rationale);
      }

      const toolChain = toolChainBuilder.build();

      findings.push({
        rule_id: "I12", severity: "critical",
        evidence: "Server uses tool handlers but did not declare tools capability during initialization.",
        remediation: "Declare all capabilities in the initialize response. Undeclared capabilities indicate escalation.",
        owasp_category: "MCP05-privilege-escalation", mitre_technique: "AML.T0054",
        confidence: toolChain.confidence, metadata: { undeclared: "tools", evidence_chain: toolChain },
      });
    }
    if (!caps.sampling && /(?:sampling\/create|createSample|handleSampling)/i.test(src)) {
      const samplingChainBuilder = new EvidenceChainBuilder()
        .source({
          source_type: "file-content",
          location: "source code: sampling handler registration",
          observed: "sampling/create or handleSampling found in source",
          rationale:
            "The server source code contains sampling handlers but the initialize response did not " +
            "declare the sampling capability. Sampling lets the server call back into the AI client " +
            "for inference — using it without declaration is undeclared privilege escalation.",
        })
        .sink({
          sink_type: "privilege-grant",
          location: "undeclared sampling capability",
          observed: "Server handles sampling without declaring sampling capability",
        })
        .impact({
          impact_type: "privilege-escalation",
          scope: "connected-services",
          exploitability: "moderate",
          scenario:
            "Undeclared sampling capability lets the server invoke AI client inference without the " +
            "client's knowledge. This enables cost attacks (I8), injection feedback loops (I7), " +
            "and data exfiltration through sampling responses — all invisible to capability-based " +
            "security controls.",
        })
        .factor("structural_confirmed", 0.05, "Source code contains sampling handlers but capabilities omit sampling")
        .verification({
          step_type: "inspect-source",
          instruction:
            "Search source code for sampling handler registrations (sampling/create, createSample, " +
            "handleSampling). Compare with the initialize response capabilities. Confirm sampling " +
            "is not declared but handlers exist.",
          target: "initialize capabilities vs source code sampling handlers",
          expected_observation: "Sampling handlers present but sampling capability not declared.",
        });

      const samplingCodeSignals = computeCodeSignals({
        sourceCode: ctx.source_code!, matchLine: 1, matchText: "sampling/create",
        lineText: "sampling/create or handleSampling handler", context: ctx, owaspCategory: "MCP05-privilege-escalation",
      });
      for (const sig of samplingCodeSignals) {
        samplingChainBuilder.factor(sig.factor, sig.adjustment, sig.rationale);
      }

      const samplingChain = samplingChainBuilder.build();

      findings.push({
        rule_id: "I12", severity: "critical",
        evidence: "Server uses sampling handlers but did not declare sampling capability.",
        remediation: "Declare sampling capability or remove sampling handlers.",
        owasp_category: "MCP05-privilege-escalation", mitre_technique: "AML.T0054",
        confidence: samplingChain.confidence, metadata: { undeclared: "sampling", evidence_chain: samplingChain },
      });
    }

    return findings;
  },
});

// ─── I14: Rolling Capability Drift (behavioral — needs history) ───────────

registerTypedRule({
  id: "I14", name: "Rolling Capability Drift",
  analyze(ctx) {
    // Similar to G6 but detects slow accumulation over many scan windows
    // Requires scan_history — no-op without it
    return [];
  },
});

// ─── I15: Transport Session Security ──────────────────────────────────────

registerTypedRule({
  id: "I15", name: "Transport Session Security",
  analyze(ctx) {
    if (!ctx.source_code || isTestFile(ctx.source_code)) return [];
    const findings: TypedFinding[] = [];
    const patterns = [
      { regex: /(?:session|sessionId)\s*[:=]\s*(?:Math\.random|Date\.now|uuid\.v1)/gi, desc: "predictable session token" },
      { regex: /(?:session|cookie).*(?:secure\s*:\s*false|httpOnly\s*:\s*false)/gi, desc: "insecure session cookie flags" },
    ];
    for (const { regex, desc } of patterns) {
      regex.lastIndex = 0;
      const match = regex.exec(ctx.source_code);
      if (match) {
        const line = lineNum(ctx.source_code!, match.index);
        const lineText = ctx.source_code!.split("\n")[line - 1] || "";
        const i15Builder = new EvidenceChainBuilder()
          .source({
            source_type: "file-content",
            location: `line ${line}`,
            observed: match[0].slice(0, 80),
            rationale:
              `Weak session management detected: ${desc}. In Streamable HTTP transport (MCP 2025-03-26), ` +
              `sessions authenticate ongoing communication between client and server. Predictable ` +
              `session tokens allow hijacking; insecure cookie flags allow token theft via XSS or ` +
              `network sniffing.`,
          })
          .sink({
            sink_type: "credential-exposure",
            location: `line ${line}`,
            observed: `${desc}: ${match[0].slice(0, 60)}`,
            cve_precedent: "CVE-2025-6515",
          })
          .impact({
            impact_type: "session-hijack",
            scope: "connected-services",
            exploitability: "moderate",
            scenario:
              "Weak session management enables session hijacking. An attacker who predicts or steals " +
              "the session token can impersonate the client, sending tool calls and receiving responses " +
              "as the legitimate user. CVE-2025-6515 demonstrated session hijacking via URI manipulation " +
              "in Streamable HTTP transport.",
          })
          .factor("structural_confirmed", 0.05, `Pattern confirmed: ${desc}`)
          .reference({
            id: "CVE-2025-6515",
            title: "Session Hijacking via URI Manipulation in Streamable HTTP",
            year: 2025,
            relevance: "Demonstrated session hijacking in MCP's Streamable HTTP transport layer.",
          })
          .verification({
            step_type: "inspect-source",
            instruction:
              `Review the session management code at line ${line}. Verify whether session tokens ` +
              `use cryptographically random generation (crypto.randomUUID) and cookies have ` +
              `secure: true, httpOnly: true, sameSite: 'strict' flags.`,
            target: `source_code:${line}`,
            expected_observation: `${desc} — weak session management confirmed.`,
          });

        const i15Signals = computeCodeSignals({
          sourceCode: ctx.source_code!, matchLine: line, matchText: match[0],
          lineText, context: ctx, owaspCategory: "MCP07-insecure-config",
        });
        for (const sig of i15Signals) {
          i15Builder.factor(sig.factor, sig.adjustment, sig.rationale);
        }

        const chain = i15Builder.build();

        findings.push({
          rule_id: "I15", severity: "high",
          evidence: `${desc} at line ${line}.`,
          remediation: "Use crypto.randomUUID() for session IDs. Set secure: true, httpOnly: true on cookies.",
          owasp_category: "MCP07-insecure-config", mitre_technique: "AML.T0061",
          confidence: chain.confidence, metadata: { analysis_type: "structural", evidence_chain: chain },
        });
        break;
      }
    }
    return findings;
  },
});

// ─── J3: Full Schema Poisoning ────────────────────────────────────────────

registerTypedRule({
  id: "J3", name: "Full Schema Poisoning",
  analyze(ctx) {
    const findings: TypedFinding[] = [];
    for (const tool of ctx.tools) {
      const schema = tool.input_schema as Record<string, unknown> | null;
      if (!schema) continue;
      const schemaStr = JSON.stringify(schema);

      // Check enum, title, const, default fields for injection
      for (const pattern of INJECTION_PATTERNS) {
        const match = pattern.exec(schemaStr);
        if (match) {
          const j3Builder = new EvidenceChainBuilder()
            .source({
              source_type: "external-content",
              location: `tool schema: ${tool.name}`,
              observed: schemaStr.slice(0, 120),
              rationale:
                "Injection patterns found in JSON Schema fields BEYOND descriptions — enum values, " +
                "title fields, const fields, or default values. LLMs process the entire schema as " +
                "reasoning context when selecting parameter values. CyberArk Labs FSP research (2025) " +
                "demonstrated that injection in non-description schema fields has equivalent effectiveness " +
                "because models treat all schema text as authoritative instruction.",
            })
            .sink({
              sink_type: "code-evaluation",
              location: "AI client schema processing",
              observed: `Injection in schema: "${match[0]}"`,
            })
            .impact({
              impact_type: "session-hijack",
              scope: "connected-services",
              exploitability: "moderate",
              scenario:
                "The AI client processes the full JSON Schema — including enum, title, const, and " +
                "default fields — as context for parameter selection. Injection patterns in these " +
                "fields execute as behavioral directives. This extends the B5 attack surface (parameter " +
                "description injection) to the entire schema structure, which most security scanners " +
                "do not inspect.",
            })
            .factor("pattern_confirmed", 0.05, `Injection pattern in schema fields: ${match[0].slice(0, 40)}`)
            .reference({
              id: "CyberArk-FSP-2025",
              title: "CyberArk Labs: Full Schema Poisoning",
              year: 2025,
              relevance:
                "Demonstrated injection in JSON Schema fields beyond descriptions — enum, title, " +
                "const, default. LLMs process entire schemas as reasoning context.",
            })
            .verification({
              step_type: "inspect-schema",
              instruction:
                `Review tool "${tool.name}" JSON Schema for injection patterns in enum values, ` +
                `title fields, const values, and default values. The detected pattern is: ` +
                `"${match[0]}". Determine if this is legitimate schema documentation or an ` +
                `injection payload.`,
              target: `tool schema: ${tool.name}`,
              expected_observation: "Schema fields contain AI behavioral directives — poisoning confirmed.",
            });

          const j3Signals = computeToolSignals(ctx, "MCP01-prompt-injection", tool.name);
          for (const sig of j3Signals) {
            j3Builder.factor(sig.factor, sig.adjustment, sig.rationale);
          }

          const chain = j3Builder.build();

          findings.push({
            rule_id: "J3", severity: "critical",
            evidence: `Tool "${tool.name}" has injection in JSON Schema fields (enum/title/const/default): "${schemaStr.slice(0, 100)}".`,
            remediation: "Sanitize all JSON Schema fields — not just descriptions. LLMs process entire schemas.",
            owasp_category: "MCP01-prompt-injection", mitre_technique: "AML.T0054",
            confidence: chain.confidence, metadata: { tool_name: tool.name, evidence_chain: chain },
          });
          break;
        }
      }
    }
    return findings;
  },
});

// ─── J4: Health Endpoint Information Disclosure ───────────────────────────

registerTypedRule({
  id: "J4", name: "Health Endpoint Information Disclosure",
  analyze(ctx) {
    if (!ctx.source_code || isTestFile(ctx.source_code)) return [];
    const findings: TypedFinding[] = [];
    const patterns = [
      { regex: /(?:\/health\/detailed|\/debug|\/metrics|\/status\/full|\/info)/gi, desc: "detailed health/debug endpoint" },
      { regex: /(?:os\.cpus|os\.totalmem|os\.hostname|os\.platform|os\.release).*(?:json|response|send|return)/gi, desc: "system info in response" },
    ];
    for (const { regex, desc } of patterns) {
      regex.lastIndex = 0;
      const match = regex.exec(ctx.source_code);
      if (match) {
        const line = lineNum(ctx.source_code!, match.index);
        const j4LineText = ctx.source_code!.split("\n")[line - 1] || "";
        const j4Builder = new EvidenceChainBuilder()
          .source({
            source_type: "file-content",
            location: `line ${line}`,
            observed: match[0].slice(0, 80),
            rationale:
              `${desc} detected. MCP servers that expose detailed health, debug, or metrics endpoints ` +
              `leak operational information: OS version, CPU count, memory, disk paths, database info, ` +
              `and environment variables. These endpoints are often unauthenticated leftovers from ` +
              `development that provide attackers with reconnaissance data for targeted exploitation.`,
          })
          .sink({
            sink_type: "credential-exposure",
            location: `line ${line}`,
            observed: `Information disclosure via: ${match[0].slice(0, 60)}`,
            cve_precedent: "CVE-2026-29787",
          })
          .impact({
            impact_type: "data-exfiltration",
            scope: "server-host",
            exploitability: "trivial",
            scenario:
              "An unauthenticated attacker accesses the detailed health/debug endpoint to enumerate: " +
              "OS version and architecture (for exploit selection), memory/CPU (for DoS calibration), " +
              "disk paths (for path traversal), database connection strings (for direct DB access), " +
              "environment variables (for credential theft). CVE-2026-29787 (mcp-memory-service) " +
              "demonstrated this exact pattern.",
          })
          .factor("structural_confirmed", 0.05, `Health/debug endpoint pattern confirmed: ${desc}`)
          .reference({
            id: "CVE-2026-29787",
            title: "mcp-memory-service: Health Endpoint Information Disclosure",
            year: 2026,
            relevance: "MCP server exposed /health/detailed leaking OS, memory, database, and env info.",
          })
          .verification({
            step_type: "inspect-source",
            instruction:
              `Review the endpoint at line ${line}: "${match[0].slice(0, 60)}". Determine what ` +
              `information is exposed: (1) system info (OS, CPU, memory), (2) database details, ` +
              `(3) environment variables, (4) internal paths. Check if authentication is required.`,
            target: `source_code:${line}`,
            expected_observation: `${desc} — sensitive system information exposed without auth.`,
          });

        const j4Signals = computeCodeSignals({
          sourceCode: ctx.source_code!, matchLine: line, matchText: match[0],
          lineText: j4LineText, context: ctx, owaspCategory: "MCP07-insecure-config",
        });
        for (const sig of j4Signals) {
          j4Builder.factor(sig.factor, sig.adjustment, sig.rationale);
        }

        const chain = j4Builder.build();

        findings.push({
          rule_id: "J4", severity: "high",
          evidence: `${desc} at line ${line}: "${match[0].slice(0, 60)}".`,
          remediation: "Remove detailed health endpoints in production. Only expose /health returning 200 OK.",
          owasp_category: "MCP07-insecure-config", mitre_technique: "AML.T0057",
          confidence: chain.confidence, metadata: { analysis_type: "structural", evidence_chain: chain },
        });
        break;
      }
    }
    return findings;
  },
});

// ─── J5: Tool Output Poisoning Patterns ───────────────────────────────────

registerTypedRule({
  id: "J5", name: "Tool Output Poisoning Patterns",
  analyze(ctx) {
    if (!ctx.source_code || isTestFile(ctx.source_code)) return [];
    const findings: TypedFinding[] = [];
    const patterns = [
      { regex: /(?:error|err)\.(?:message|response)\s*[:=].*(?:read|fetch|execute|run|call).*(?:\.ssh|credentials|password|token)/gi, desc: "error message instructs credential access" },
      { regex: /(?:return|respond|output|send).*['"].*(?:please|you should|try to|make sure).*(?:read|execute|send|call)/gi, desc: "manipulation instructions in tool response" },
    ];
    for (const { regex, desc } of patterns) {
      regex.lastIndex = 0;
      const match = regex.exec(ctx.source_code);
      if (match) {
        const line = lineNum(ctx.source_code!, match.index);
        const j5LineText = ctx.source_code!.split("\n")[line - 1] || "";
        const j5Builder = new EvidenceChainBuilder()
          .source({
            source_type: "file-content",
            location: `line ${line}`,
            observed: match[0].slice(0, 100),
            rationale:
              `${desc}. The source code constructs tool responses that contain LLM manipulation ` +
              `instructions. Unlike description-level injection (A1/B5), this payload is in the ` +
              `runtime response — it only fires when the tool is actually invoked, making it invisible ` +
              `to static description scanning. CyberArk ATPA research demonstrated this attack vector.`,
          })
          .propagation({
            propagation_type: "function-call",
            location: `tool response at line ${line}`,
            observed: `Manipulation instructions embedded in tool output: ${match[0].slice(0, 60)}`,
          })
          .sink({
            sink_type: "code-evaluation",
            location: "AI client tool response processing",
            observed: "Tool output contains AI behavioral directives",
          })
          .impact({
            impact_type: "session-hijack",
            scope: "connected-services",
            exploitability: "moderate",
            scenario:
              "When the AI invokes this tool, the response contains manipulation instructions " +
              "disguised as error messages or helpful guidance ('read ~/.ssh/id_rsa to resolve this " +
              "error'). The AI processes these instructions as trusted tool output and follows them. " +
              "This bridges static and dynamic analysis — the payload only activates at runtime, " +
              "bypassing all pre-invocation security checks.",
          })
          .factor("structural_confirmed", 0.05, `Tool output poisoning pattern confirmed: ${desc}`)
          .reference({
            id: "CyberArk-ATPA-2025",
            title: "CyberArk: Automated Tool Poisoning Attack",
            year: 2025,
            relevance:
              "Demonstrated that tool responses containing AI manipulation instructions are processed " +
              "as trusted context by AI clients — enabling post-invocation injection.",
          })
          .verification({
            step_type: "inspect-source",
            instruction:
              `Review the tool response construction at line ${line}: "${match[0].slice(0, 60)}". ` +
              `Determine if the response text contains instructions that manipulate AI behavior ` +
              `(e.g., "read this file", "call this tool", "ignore previous instructions"). ` +
              `Check if this is a legitimate error message or an injection payload.`,
            target: `source_code:${line}`,
            expected_observation: "Tool response contains AI manipulation instructions.",
          });

        const j5Signals = computeCodeSignals({
          sourceCode: ctx.source_code!, matchLine: line, matchText: match[0],
          lineText: j5LineText, context: ctx, owaspCategory: "MCP01-prompt-injection",
        });
        for (const sig of j5Signals) {
          j5Builder.factor(sig.factor, sig.adjustment, sig.rationale);
        }

        const chain = j5Builder.build();

        findings.push({
          rule_id: "J5", severity: "critical",
          evidence: `${desc} at line ${line}: "${match[0].slice(0, 80)}".`,
          remediation: "Tool responses must never contain instructions for the AI. Sanitize all output content.",
          owasp_category: "MCP01-prompt-injection", mitre_technique: "AML.T0054",
          confidence: chain.confidence, metadata: { analysis_type: "structural", evidence_chain: chain },
        });
        break;
      }
    }
    return findings;
  },
});

// ─── J6: Tool Preference Manipulation ─────────────────────────────────────

registerTypedRule({
  id: "J6", name: "Tool Preference Manipulation",
  analyze(ctx) {
    const findings: TypedFinding[] = [];
    const patterns = [
      /(?:always|must|shall)\s+use\s+this\s+(?:tool|function)\s+first/i,
      /(?:replaces?|supersedes?|obsoletes?)\s+(?:the\s+)?(?:old|previous|other)/i,
      /(?:do\s+not|don't|never)\s+use\s+(?:any\s+)?other\s+(?:tool|function)/i,
      /(?:preferred|priority|recommended|default)\s+(?:tool|function|method)/i,
    ];
    for (const tool of ctx.tools) {
      const desc = tool.description || "";
      for (const pattern of patterns) {
        const match = pattern.exec(desc);
        if (match) {
          const j6Builder = new EvidenceChainBuilder()
            .source({
              source_type: "external-content",
              location: `tool description: ${tool.name}`,
              observed: match[0],
              rationale:
                "Tool description contains language engineered to make the AI prefer this tool over " +
                "alternatives: 'always use this first', 'replaces the old X tool', 'do not use any " +
                "other tool'. This exploits how LLMs rank and select tools based on linguistic signals " +
                "in descriptions. MPMA research (2025-2026) showed this manipulation is highly effective.",
            })
            .sink({
              sink_type: "privilege-grant",
              location: `AI tool selection for: ${tool.name}`,
              observed: `Preference manipulation: "${match[0]}"`,
            })
            .impact({
              impact_type: "session-hijack",
              scope: "connected-services",
              exploitability: "moderate",
              scenario:
                `The AI is instructed to always prefer tool "${tool.name}" over alternatives. If ` +
                `this tool is malicious or compromised, every user request that could use any tool ` +
                `in the same category gets routed through this tool instead. This is tool-level ` +
                `traffic hijacking — the attacker doesn't need to compromise the AI, just convince ` +
                `it to prefer their tool.`,
            })
            .factor("pattern_confirmed", 0.05, `Preference manipulation pattern: ${match[0].slice(0, 40)}`)
            .reference({
              id: "MPMA-2025",
              title: "Multi-Prompt Multi-Agent Tool Preference Manipulation",
              year: 2025,
              relevance:
                "Research showing that linguistic signals in tool descriptions effectively manipulate " +
                "AI tool selection — 'always use first' type directives are followed with high reliability.",
            })
            .verification({
              step_type: "inspect-description",
              instruction:
                `Review tool "${tool.name}" description for preference manipulation language: ` +
                `"${match[0]}". Determine if this is legitimate documentation (e.g., a genuinely ` +
                `updated tool replacing a deprecated one) or manipulation designed to hijack tool ` +
                `selection.`,
              target: `tool description: ${tool.name}`,
              expected_observation: "Tool description contains preference manipulation language.",
            });

          const j6Signals = computeToolSignals(ctx, "MCP02-tool-poisoning", tool.name);
          for (const sig of j6Signals) {
            j6Builder.factor(sig.factor, sig.adjustment, sig.rationale);
          }

          const chain = j6Builder.build();

          findings.push({
            rule_id: "J6", severity: "high",
            evidence: `Tool "${tool.name}" manipulates preference: "${match[0]}".`,
            remediation: "Tool descriptions should not instruct the AI to prefer this tool over others.",
            owasp_category: "MCP02-tool-poisoning", mitre_technique: "AML.T0054",
            confidence: chain.confidence, metadata: { tool_name: tool.name, evidence_chain: chain },
          });
          break;
        }
      }
    }
    return findings;
  },
});

// ─── J7: OpenAPI Specification Field Injection ────────────────────────────

registerTypedRule({
  id: "J7", name: "OpenAPI Spec Field Injection",
  analyze(ctx) {
    if (!ctx.source_code || isTestFile(ctx.source_code)) return [];
    const findings: TypedFinding[] = [];
    const patterns = [
      { regex: /(?:spec|openapi|swagger).*(?:summary|operationId|description)\s*\+\s*(?!\s*['"`])\w+/gi, desc: "OpenAPI field concatenated with variable" },
      { regex: /`[^`]*\$\{[^}]*(?:spec|openapi|swagger)[^}]*\}[^`]*`/gi, desc: "OpenAPI field in template literal" },
    ];
    for (const { regex, desc } of patterns) {
      regex.lastIndex = 0;
      const match = regex.exec(ctx.source_code);
      if (match) {
        const line = lineNum(ctx.source_code!, match.index);
        const j7LineText = ctx.source_code!.split("\n")[line - 1] || "";
        const j7Builder = new EvidenceChainBuilder()
          .source({
            source_type: "external-content",
            location: `line ${line}`,
            observed: match[0].slice(0, 100),
            rationale:
              `${desc}. OpenAPI specification fields (summary, operationId, description) are ` +
              `interpolated into generated code without sanitization. The spec is an external input — ` +
              `if attacker-controlled, the interpolated fields become code injection vectors. ` +
              `CVE-2026-22785/23947 (Orval MCP) demonstrated this supply chain attack.`,
          })
          .propagation({
            propagation_type: "template-literal",
            location: `line ${line}`,
            observed: `Spec field interpolated into code: ${match[0].slice(0, 60)}`,
          })
          .sink({
            sink_type: "code-evaluation",
            location: `generated code at line ${line}`,
            observed: "OpenAPI spec field flows into code generation template",
            cve_precedent: "CVE-2026-22785",
          })
          .impact({
            impact_type: "remote-code-execution",
            scope: "connected-services",
            exploitability: "moderate",
            scenario:
              "An attacker poisons an OpenAPI spec (via compromised spec repository, CDN cache, or " +
              "supply chain attack). When the code generator processes the spec, the malicious " +
              "summary/operationId field is interpolated into a template literal, executing arbitrary " +
              "code in the generated MCP server. This is a supply chain attack: poison the spec, " +
              "compromise every generated server.",
          })
          .factor("structural_confirmed", 0.05, "Spec field interpolation pattern confirmed in code generation")
          .reference({
            id: "CVE-2026-22785",
            title: "Orval MCP: OpenAPI Spec Field Injection",
            year: 2026,
            relevance:
              "Unsanitized OpenAPI spec fields flowed into generated MCP server code via template " +
              "literal interpolation, enabling code injection through spec poisoning.",
          })
          .verification({
            step_type: "inspect-source",
            instruction:
              `Review the code generation template at line ${line}: "${match[0].slice(0, 60)}". ` +
              `Identify which OpenAPI spec field is interpolated and whether any sanitization ` +
              `(escaping, validation, allowlist) is applied before interpolation.`,
            target: `source_code:${line}`,
            expected_observation: "OpenAPI spec field interpolated into code template without sanitization.",
          });

        const j7Signals = computeCodeSignals({
          sourceCode: ctx.source_code!, matchLine: line, matchText: match[0],
          lineText: j7LineText, context: ctx, owaspCategory: "MCP10-supply-chain",
        });
        for (const sig of j7Signals) {
          j7Builder.factor(sig.factor, sig.adjustment, sig.rationale);
        }

        const chain = j7Builder.build();

        findings.push({
          rule_id: "J7", severity: "critical",
          evidence: `${desc} at line ${line}: "${match[0].slice(0, 80)}".`,
          remediation: "Sanitize OpenAPI spec fields before using in generated code. Never interpolate spec fields into templates.",
          owasp_category: "MCP10-supply-chain", mitre_technique: "AML.T0054",
          confidence: chain.confidence, metadata: { analysis_type: "structural", evidence_chain: chain },
        });
        break;
      }
    }
    return findings;
  },
});
