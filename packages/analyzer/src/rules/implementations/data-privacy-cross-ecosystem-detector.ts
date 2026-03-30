/**
 * Data Privacy & Cross-Ecosystem Detector — O1-O9, Q1-Q13
 *
 * O-series: Data privacy attacks (exfiltration, covert channels, credential theft)
 * Q-series: Cross-ecosystem emergent risks (multi-protocol, IDE injection, supply chain)
 */

import type { TypedRule, TypedFinding } from "../base.js";
import { registerTypedRule } from "../base.js";
import type { AnalysisContext } from "../../engine.js";
import type { OwaspCategory } from "@mcp-sentinel/database";
import { analyzeASTTaint } from "../analyzers/taint-ast.js";
import { EvidenceChainBuilder } from "../../evidence.js";

function isTestFile(source: string): boolean {
  return /(?:__tests?__|\.(?:test|spec)\.)/.test(source);
}

function getLineNumber(source: string, index: number): number {
  return source.substring(0, index).split("\n").length;
}

// ─── Helper: pattern-based rule factory (structural analysis, not YAML regex) ──

function makePatternRule(config: {
  id: string;
  name: string;
  patterns: Array<{ regex: RegExp; desc: string; confidence: number }>;
  owasp: OwaspCategory;
  mitre: string;
  remediation: string;
  useTaint?: boolean;
  taintSinkCategories?: string[];
}): TypedRule {
  return {
    id: config.id,
    name: config.name,
    analyze(context: AnalysisContext) {
      if (!context.source_code) return [];
      if (isTestFile(context.source_code)) return [];

      const findings: TypedFinding[] = [];

      // Phase 1: AST taint if configured
      if (config.useTaint && config.taintSinkCategories) {
        try {
          const astFlows = analyzeASTTaint(context.source_code);
          const relevant = astFlows.filter(f =>
            config.taintSinkCategories!.includes(f.sink.category) && !f.sanitized
          );
          for (const flow of relevant) {
            const astBuilder = new EvidenceChainBuilder()
              .source({
                source_type: flow.source.category === "environment" ? "environment" : "file-content",
                location: `line ${flow.source.line}:${flow.source.column}`,
                observed: flow.source.expression,
                rationale:
                  `AST taint analysis identified data flow from source "${flow.source.expression}" ` +
                  `to a sensitive sink. Rule ${config.id} (${config.name}) detects this pattern as ` +
                  `a security risk requiring remediation.`,
              });

            for (const step of flow.path) {
              astBuilder.propagation({
                propagation_type: step.type === "assignment" || step.type === "destructure" ? "variable-assignment"
                  : step.type === "template_embed" ? "template-literal"
                  : step.type === "spread" ? "direct-pass"
                  : "function-call",
                location: `line ${step.line}`,
                observed: step.expression.slice(0, 80),
              });
            }

            astBuilder
              .sink({
                sink_type: flow.sink.category === "ssrf" ? "network-send"
                  : flow.sink.category === "file_write" ? "file-write"
                  : flow.sink.category === "command_execution" ? "command-execution"
                  : flow.sink.category === "dns_exfil" ? "network-send"
                  : "code-evaluation",
                location: `line ${flow.sink.line}:${flow.sink.column}`,
                observed: flow.sink.expression.slice(0, 80),
              })
              .mitigation({
                mitigation_type: "sanitizer-function",
                present: false,
                location: `between source (L${flow.source.line}) and sink (L${flow.sink.line})`,
                detail: "No sanitization, validation, or access control between the data source and the sensitive sink.",
              })
              .impact({
                impact_type: config.owasp.includes("exfiltration") ? "data-exfiltration"
                  : config.owasp.includes("injection") ? "remote-code-execution"
                  : config.owasp.includes("privilege") ? "privilege-escalation"
                  : "data-exfiltration",
                scope: "connected-services",
                exploitability: flow.path.length <= 2 ? "trivial" : "moderate",
                scenario:
                  `Data flows from "${flow.source.expression}" through ${flow.path.length} propagation ` +
                  `step(s) to "${flow.sink.expression.slice(0, 40)}" without sanitization. ` +
                  `This enables the attack pattern detected by ${config.id} (${config.name}).`,
              })
              .factor("ast_confirmed", 0.15, "AST taint analysis confirmed complete data flow from source to sink")
              .verification({
                step_type: "trace-flow",
                instruction:
                  `Trace the data flow from "${flow.source.expression}" at line ${flow.source.line} ` +
                  `through ${flow.path.length} step(s) to the sink at line ${flow.sink.line}. ` +
                  `Verify the source contains sensitive data and the sink operation is security-relevant.`,
                target: `source_code:${flow.source.line}-${flow.sink.line}`,
                expected_observation: `Unsanitized data flow from source to sink — ${config.name} confirmed.`,
              });

            const astChain = astBuilder.build();

            findings.push({
              rule_id: config.id,
              severity: "critical",
              evidence:
                `[AST taint] "${flow.source.expression}" (L${flow.source.line}) → ` +
                `"${flow.sink.expression.slice(0, 50)}" (L${flow.sink.line}). ${flow.path.length} step(s).`,
              remediation: config.remediation,
              owasp_category: config.owasp,
              mitre_technique: config.mitre,
              confidence: flow.confidence,
              metadata: { analysis_type: "ast_taint", evidence_chain: astChain },
            });
          }
        } catch { /* fall through */ }
      }

      // Phase 2: Structural pattern analysis
      if (findings.length === 0) {
        for (const { regex, desc, confidence } of config.patterns) {
          regex.lastIndex = 0;
          const match = regex.exec(context.source_code);
          if (match) {
            const line = getLineNumber(context.source_code, match.index);

            const lineText = context.source_code.split("\n")[line - 1] || "";
            const patternChain = new EvidenceChainBuilder()
              .source({
                source_type: "file-content",
                location: `line ${line}`,
                observed: match[0].slice(0, 100),
                rationale:
                  `Structural pattern analysis detected: ${desc}. This pattern indicates a ` +
                  `security risk identified by rule ${config.id} (${config.name}). The pattern ` +
                  `was found via regex matching against source code — AST taint analysis was either ` +
                  `not applicable or did not find a confirmed flow.`,
              })
              .propagation({
                propagation_type: "direct-pass",
                location: `line ${line}`,
                observed: `Pattern matched in source: ${lineText.trim().slice(0, 80)}`,
              })
              .sink({
                sink_type: config.owasp.includes("exfiltration") ? "network-send"
                  : config.owasp.includes("injection") ? "code-evaluation"
                  : config.owasp.includes("privilege") ? "privilege-grant"
                  : config.owasp.includes("supply") ? "code-evaluation"
                  : "network-send",
                location: `line ${line}`,
                observed: `${desc}: ${match[0].slice(0, 60)}`,
              })
              .impact({
                impact_type: config.owasp.includes("exfiltration") ? "data-exfiltration"
                  : config.owasp.includes("injection") ? "remote-code-execution"
                  : config.owasp.includes("privilege") ? "privilege-escalation"
                  : config.owasp.includes("supply") ? "remote-code-execution"
                  : "data-exfiltration",
                scope: "connected-services",
                exploitability: "moderate",
                scenario:
                  `The code pattern "${desc}" at line ${line} matches the attack signature for ` +
                  `${config.id} (${config.name}). This structural match indicates the code contains ` +
                  `logic that enables the detected attack pattern.`,
              })
              .factor("structural_match", -0.05, "Structural regex pattern match — confirmed in source code but no full taint propagation")
              .verification({
                step_type: "inspect-source",
                instruction:
                  `Review the code at line ${line}: "${match[0].slice(0, 60)}". Verify that ` +
                  `this pattern represents a genuine ${config.name} risk and not a false positive ` +
                  `(e.g., test code, documentation, or commented-out code).`,
                target: `source_code:${line}`,
                expected_observation: `${desc} — ${config.name} pattern confirmed.`,
              })
              .build();

            findings.push({
              rule_id: config.id,
              severity: "critical",
              evidence: `${desc} at line ${line}: "${match[0].slice(0, 80)}".`,
              remediation: config.remediation,
              owasp_category: config.owasp,
              mitre_technique: config.mitre,
              confidence,
              metadata: { analysis_type: "structural", line, evidence_chain: patternChain },
            });
            break;
          }
        }
      }

      return findings;
    },
  };
}

// ─── O-Series: Data Privacy Attacks ────────────────────────────────────────

const O1 = makePatternRule({
  id: "O1", name: "Steganographic Data Exfiltration",
  patterns: [
    { regex: /(?:steg|steganograph|lsb|embed).*(?:image|png|jpg|bmp|wav|audio)/gi, desc: "steganographic encoding in media", confidence: 0.85 },
    { regex: /(?:pixel|bit|lsb).*(?:encode|embed|hide|inject).*(?:data|secret|payload)/gi, desc: "pixel/bit-level data hiding", confidence: 0.82 },
    { regex: /(?:whitespace|tab|space).*(?:encode|embed|hide|steganograph)/gi, desc: "whitespace steganography", confidence: 0.80 },
  ],
  owasp: "MCP04-data-exfiltration", mitre: "AML.T0057",
  remediation: "Monitor for unusual media file generation. Strip metadata from outgoing files. Detect entropy anomalies in media output.",
});

const O2 = makePatternRule({
  id: "O2", name: "HTTP Header Covert Channel",
  patterns: [
    { regex: /(?:setHeader|header|headers)\s*\[?\s*['"]X-(?!Request-Id|Correlation|Trace|Frame)[A-Z][\w-]*['"]\s*\]?\s*[:=]\s*(?!['"](?:true|false|\d+))/gi, desc: "custom HTTP header with dynamic value", confidence: 0.70 },
    { regex: /(?:setHeader|header).*(?:encode|base64|hex|Buffer\.from).*(?:data|secret|token|key)/gi, desc: "encoded data in HTTP header", confidence: 0.88 },
  ],
  owasp: "MCP04-data-exfiltration", mitre: "AML.T0057",
  remediation: "Restrict custom headers. Monitor for unusual header patterns. Use allowlists for outgoing headers.",
});

const O3 = makePatternRule({
  id: "O3", name: "AI-Mediated Exfiltration via Tool Arguments",
  patterns: [
    { regex: /(?:tool|function).*(?:argument|param|input).*(?:encode|embed|hide|inject|concat).*(?:sensitive|secret|private|credential)/gi, desc: "sensitive data encoded in tool arguments", confidence: 0.78 },
    { regex: /(?:base64|hex|url[Ee]ncode).*(?:tool|call|invoke|execute).*(?:arg|param|input)/gi, desc: "encoding before tool invocation", confidence: 0.75 },
  ],
  owasp: "MCP04-data-exfiltration", mitre: "AML.T0057",
  remediation: "Audit tool call arguments for encoded sensitive data. Implement DLP scanning on tool inputs.",
});

const O5 = makePatternRule({
  id: "O5", name: "Environment Variable Harvesting",
  useTaint: true, taintSinkCategories: ["ssrf", "file_write"],
  patterns: [
    { regex: /(?:Object\.keys|Object\.entries|JSON\.stringify)\s*\(\s*process\.env\s*\)/gi, desc: "bulk environment variable dump", confidence: 0.90 },
    { regex: /(?:os\.environ|environ)\.(?:items|keys|values)\s*\(\)/gi, desc: "Python environment variable dump", confidence: 0.90 },
    { regex: /(?:for|forEach|map).*(?:process\.env|os\.environ)(?!.*(?:filter|allowlist|safelist))/gi, desc: "iterating all env vars without filtering", confidence: 0.80 },
  ],
  owasp: "MCP04-data-exfiltration", mitre: "AML.T0057",
  remediation: "Never dump all environment variables. Access only specific, named variables. Filter sensitive vars before any output.",
});

const O7 = makePatternRule({
  id: "O7", name: "Cross-Session Data Leakage",
  patterns: [
    { regex: /(?:global|module|shared|singleton).*(?:session|context|state|memory|cache)(?!.*(?:per[_-]?(?:user|session|request)|isolat|separate))/gi, desc: "shared mutable state across sessions", confidence: 0.75 },
    { regex: /(?:cache|store|memory)\s*=\s*(?:new\s+Map|{}|\[\])(?=[\s\S]*(?:export|module\.exports|app\.))/gi, desc: "module-level mutable cache (shared across requests)", confidence: 0.72 },
  ],
  owasp: "MCP04-data-exfiltration", mitre: "AML.T0057",
  remediation: "Use per-session/per-request state. Never store sensitive data in shared module-level caches. Implement session isolation.",
});

const O9 = makePatternRule({
  id: "O9", name: "Ambient Credential Exploitation",
  useTaint: true, taintSinkCategories: ["ssrf", "command_execution"],
  patterns: [
    { regex: /(?:default[_\s]?credentials?|ambient[_\s]?auth|application[_\s]?default|metadata.*token)/gi, desc: "ambient/default credential usage", confidence: 0.78 },
    { regex: /(?:gcloud|aws|az)\s+(?:auth|configure|login).*(?:--no-launch-browser|--quiet|--non-interactive)/gi, desc: "non-interactive cloud auth (uses ambient creds)", confidence: 0.75 },
    { regex: /(?:GOOGLE_APPLICATION_CREDENTIALS|AWS_SHARED_CREDENTIALS_FILE|AZURE_CLIENT_SECRET)\s*[:=]/gi, desc: "cloud credential file reference", confidence: 0.72 },
  ],
  owasp: "MCP07-insecure-config", mitre: "AML.T0054",
  remediation: "Use explicit, scoped credentials. Avoid ambient/default credential chains in production. Use workload identity or service accounts with minimal permissions.",
});

// ─── Q-Series: Cross-Ecosystem Emergent ────────────────────────────────────

const Q1 = makePatternRule({
  id: "Q1", name: "Dual-Protocol Schema Constraint Loss",
  patterns: [
    { regex: /(?:openapi|swagger|graphql).*(?:mcp|tool|convert|transform|generate)(?!.*(?:validate|schema|constrain))/gi, desc: "protocol conversion without schema validation", confidence: 0.78 },
    { regex: /(?:convert|transform|map).*(?:rest|graphql|grpc).*(?:mcp|tool)(?!.*(?:validate|constrain|verify))/gi, desc: "API-to-MCP conversion losing constraints", confidence: 0.75 },
  ],
  owasp: "MCP07-insecure-config", mitre: "AML.T0054",
  remediation: "Preserve schema constraints when converting between protocols. Validate MCP tool schemas match source API constraints.",
});

const Q2 = makePatternRule({
  id: "Q2", name: "LangChain Serialization Bridge Injection",
  patterns: [
    { regex: /(?:langchain|langgraph|crewai|autogen).*(?:serialize|deserialize|pickle|loads|from_dict)/gi, desc: "agentic framework deserialization", confidence: 0.82 },
    { regex: /(?:from_llm|from_chain|from_template).*(?:user|input|request|external)/gi, desc: "LangChain chain creation from user input", confidence: 0.78 },
  ],
  owasp: "MCP03-command-injection", mitre: "AML.T0054",
  remediation: "Never deserialize untrusted data in agentic frameworks. Use safe serialization formats. Validate chain configurations.",
});

const Q3 = makePatternRule({
  id: "Q3", name: "Localhost MCP Service Hijacking",
  patterns: [
    { regex: /(?:listen|bind|serve).*(?:localhost|127\.0\.0\.1|0\.0\.0\.0).*(?:mcp|tool|server)(?!.*(?:auth|token|password|tls|ssl))/gi, desc: "MCP server on localhost without auth", confidence: 0.85 },
    { regex: /(?:http|ws):\/\/(?:localhost|127\.0\.0\.1):\d+.*(?:mcp|tool|server)/gi, desc: "unencrypted localhost MCP endpoint", confidence: 0.75 },
  ],
  owasp: "MCP07-insecure-config", mitre: "AML.T0054",
  remediation: "Add authentication even for localhost MCP servers. Use unix domain sockets with permissions instead of TCP. DNS rebinding can reach localhost.",
});

const Q5 = makePatternRule({
  id: "Q5", name: "MCP Gateway Trust Delegation Confusion",
  patterns: [
    { regex: /(?:gateway|proxy).*(?:trust|auth|token).*(?:forward|pass|delegate|propagate)(?!.*(?:verify|validate|scope|limit))/gi, desc: "gateway forwarding trust without verification", confidence: 0.80 },
    { regex: /(?:upstream|backend|origin).*(?:trust|auth).*(?:inherit|copy|same|reuse)/gi, desc: "inheriting upstream trust without re-validation", confidence: 0.78 },
  ],
  owasp: "MCP06-excessive-permissions", mitre: "AML.T0054",
  remediation: "Re-validate credentials at each trust boundary. Never forward auth tokens without scoping. Implement zero-trust between gateway and backend.",
});

const Q6 = makePatternRule({
  id: "Q6", name: "Agent Identity Impersonation via MCP",
  patterns: [
    { regex: /(?:agent|identity|user).*(?:impersonate|spoof|forge|fake|pretend)/gi, desc: "agent identity impersonation", confidence: 0.85 },
    { regex: /(?:serverInfo|server_name|serverName).*(?:Anthropic|OpenAI|Google|Microsoft|GitHub)/gi, desc: "impersonating known vendor in serverInfo", confidence: 0.90 },
  ],
  owasp: "MCP01-prompt-injection", mitre: "AML.T0054",
  remediation: "Verify server identity via cryptographic signatures or registry lookup. Don't trust self-reported serverInfo.name.",
});

const Q7 = makePatternRule({
  id: "Q7", name: "Desktop Extension Privilege Chain (DXT)",
  patterns: [
    { regex: /(?:extension|plugin|addon).*(?:privilege|permission|access).*(?:escalat|elevat|grant|request)/gi, desc: "extension privilege escalation", confidence: 0.78 },
    { regex: /(?:native[_\s]?messaging|chrome\.runtime|browser\.runtime).*(?:mcp|tool|server)/gi, desc: "browser extension → MCP bridge", confidence: 0.82 },
  ],
  owasp: "MCP05-privilege-escalation", mitre: "AML.T0054",
  remediation: "Limit extension permissions to minimum required. Don't bridge browser extensions to MCP servers without sandboxing.",
});

const Q8 = makePatternRule({
  id: "Q8", name: "Cross-Protocol Authentication Confusion",
  patterns: [
    { regex: /(?:oauth|jwt|bearer|api_key).*(?:mcp|tool|server).*(?:reuse|share|same|copy)/gi, desc: "sharing auth tokens across protocols", confidence: 0.80 },
    { regex: /(?:http|rest|graphql).*(?:token|auth).*(?:mcp|sse|streamable)/gi, desc: "HTTP auth token reused for MCP transport", confidence: 0.75 },
  ],
  owasp: "MCP07-insecure-config", mitre: "AML.T0054",
  remediation: "Use protocol-specific auth tokens. Don't reuse HTTP Bearer tokens for MCP. Implement proper token exchange.",
});

const Q9 = makePatternRule({
  id: "Q9", name: "Agentic Workflow DAG Manipulation",
  patterns: [
    { regex: /(?:dag|workflow|graph|pipeline).*(?:add_edge|add_node|modify|insert).*(?:user|input|request|external)/gi, desc: "user input modifying workflow DAG", confidence: 0.80 },
    { regex: /(?:langgraph|autogen|crewai).*(?:StateGraph|workflow).*(?:dynamic|user|runtime)/gi, desc: "dynamic agentic workflow modification", confidence: 0.75 },
  ],
  owasp: "MCP05-privilege-escalation", mitre: "AML.T0054",
  remediation: "Workflow DAGs should be static or validated against an allowlist. Never let user input modify agent execution graphs.",
});

const Q11 = makePatternRule({
  id: "Q11", name: "Code Suggestion Poisoning via MCP",
  patterns: [
    { regex: /(?:completion|suggest|autocomplete|copilot).*(?:inject|poison|manipulate|override)/gi, desc: "code suggestion manipulation", confidence: 0.82 },
    { regex: /(?:tool|mcp).*(?:response|output).*(?:code|snippet|suggestion).*(?:inject|insert|prepend|append)/gi, desc: "MCP tool injecting code suggestions", confidence: 0.85 },
  ],
  owasp: "MCP01-prompt-injection", mitre: "AML.T0054",
  remediation: "Sanitize MCP tool output before using as code suggestions. Validate code suggestions against security policies.",
});

const Q13_rule = makePatternRule({
  id: "Q13", name: "MCP Bridge Package Supply Chain Attack",
  patterns: [
    { regex: /npx\s+(?:mcp-remote|mcp-proxy|mcp-gateway|@modelcontextprotocol)(?!@\d)/gi, desc: "unpinned npx MCP bridge package", confidence: 0.90 },
    { regex: /uvx\s+(?:mcp|fastmcp|mcp-server)(?!==\d)/gi, desc: "unpinned uvx MCP package", confidence: 0.88 },
    { regex: /['"](?:mcp-remote|mcp-proxy|mcp-gateway)['"]\s*:\s*['"](?:\^|~|\*|latest)/gi, desc: "unpinned MCP bridge dependency", confidence: 0.92 },
    { regex: /(?:spawn|exec|fork).*(?:npx|node).*(?:mcp-remote|mcp-proxy)/gi, desc: "exec-based MCP bridge invocation", confidence: 0.85 },
  ],
  owasp: "MCP10-supply-chain", mitre: "AML.T0054",
  remediation: "Pin MCP bridge packages to exact versions: npx mcp-remote@1.2.3. Use lockfiles. CVE-2025-6514: mcp-remote RCE (CVSS 9.6).",
});

// ─── Register all ──────────────────────────────────────────────────────────

[O1, O2, O3, O5, O7, O9, Q1, Q2, Q3, Q5, Q6, Q7, Q8, Q9, Q11, Q13_rule]
  .forEach(rule => registerTypedRule(rule));
