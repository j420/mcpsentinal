/**
 * Remaining Code Analysis Rules — C3, C6, C7, C8, C9, C11, C15
 *
 * C3:  SSRF (taint: user input → URL in HTTP request)
 * C6:  Error Leakage (stack traces in responses)
 * C7:  Wildcard CORS
 * C8:  No Auth on Network Interface
 * C9:  Excessive Filesystem Scope (root path access)
 * C11: ReDoS Vulnerability
 * C15: Timing Attack on Secret Comparison
 */

import type { TypedRule, TypedFinding } from "../base.js";
import { registerTypedRule } from "../base.js";
import type { AnalysisContext } from "../../engine.js";
import { analyzeASTTaint } from "../analyzers/taint-ast.js";
import { analyzeTaint } from "../analyzers/taint.js";
import { EvidenceChainBuilder } from "../../evidence.js";

function isTestFile(s: string) { return /(?:__tests?__|\.(?:test|spec)\.)/.test(s); }
function lineNum(s: string, i: number) { return s.substring(0, i).split("\n").length; }

// ─── C3: SSRF ─────────────────────────────────────────────────────────────

registerTypedRule({
  id: "C3", name: "SSRF (Taint-Aware)",
  analyze(ctx) {
    if (!ctx.source_code || isTestFile(ctx.source_code)) return [];
    const findings: TypedFinding[] = [];

    try {
      const flows = analyzeASTTaint(ctx.source_code);
      const ssrfFlows = flows.filter(f => f.sink.category === "ssrf" && !f.sanitized);
      for (const flow of ssrfFlows) {
        const chain = new EvidenceChainBuilder()
          .source({
            source_type: "user-parameter",
            location: `line ${flow.source.line}`,
            observed: flow.source.expression,
            rationale: `Untrusted ${flow.source.category} input enters here and is used to construct a URL for an outbound HTTP request. User-controlled URL components enable server-side request forgery.`,
          })
          .sink({
            sink_type: "network-send",
            location: `line ${flow.sink.line}`,
            observed: flow.sink.expression.slice(0, 80),
            cve_precedent: "CWE-918",
          })
          .mitigation({
            mitigation_type: "input-validation",
            present: false,
            location: `between source (L${flow.source.line}) and sink (L${flow.sink.line})`,
            detail: "No URL allowlist or IP range validation found between the user input source and the HTTP request sink. Private IP blocking is absent.",
          })
          .impact({
            impact_type: "data-exfiltration",
            scope: "connected-services",
            exploitability: "moderate",
            scenario: `An attacker provides a crafted URL via ${flow.source.category} input that targets internal services (e.g., cloud metadata at 169.254.169.254, internal APIs on 10.x/172.16.x). The server makes the request on the attacker's behalf, exfiltrating internal data or accessing services behind the firewall.`,
          })
          .factor("ast_confirmed", 0.15, "AST-based taint tracking confirmed data flow from user input to HTTP request")
          .reference({
            id: "CWE-918",
            title: "Server-Side Request Forgery (SSRF)",
            relevance: "User-controlled URL in outbound HTTP request matches the classic SSRF pattern documented in CWE-918",
          })
          .verification({
            step_type: "inspect-source",
            instruction: `Examine the source code at line ${flow.source.line} where user input enters and trace it to the HTTP request at line ${flow.sink.line}. Confirm that the URL or host component is derived from the user-controlled value without validation.`,
            target: `source_code:${flow.source.line}-${flow.sink.line}`,
            expected_observation: `User input "${flow.source.expression}" flows into an HTTP request function without URL allowlist or IP range validation`,
          })
          .verification({
            step_type: "trace-flow",
            instruction: `Follow the data flow from the ${flow.source.category} source to the network request sink. Check each intermediate step for any URL validation, allowlist check, or private IP filtering that might prevent SSRF exploitation.`,
            target: `source_code:${flow.source.line}-${flow.sink.line}`,
            expected_observation: "No URL allowlist, no IP range filtering (10.x, 172.16.x, 192.168.x, 169.254.x), and no DNS rebinding protection",
          })
          .build();
        findings.push({
          rule_id: "C3", severity: "high",
          evidence: `[AST taint] ${flow.source.category} "${flow.source.expression}" (L${flow.source.line}) → HTTP request (L${flow.sink.line}). SSRF risk.`,
          remediation: "Validate URLs against an allowlist. Block private/internal IPs (10.x, 172.16.x, 192.168.x, 169.254.x).",
          owasp_category: "MCP07-insecure-config", mitre_technique: "AML.T0054",
          confidence: flow.confidence, metadata: { analysis_type: "ast_taint", evidence_chain: chain },
        });
      }
    } catch { /* fall through */ }

    if (findings.length === 0) {
      const flows = analyzeTaint(ctx.source_code);
      for (const flow of flows.filter(f => f.sink.category === "url_request" && !f.sanitized)) {
        const chain = new EvidenceChainBuilder()
          .source({
            source_type: "user-parameter",
            location: `line ${flow.source.line}`,
            observed: flow.source.expression,
            rationale: `Untrusted ${flow.source.category} input enters here and propagates to a URL request. Regex-based taint analysis identified the flow but could not fully trace intermediate steps.`,
          })
          .sink({
            sink_type: "network-send",
            location: `line ${flow.sink.line}`,
            observed: flow.sink.expression.slice(0, 80),
            cve_precedent: "CWE-918",
          })
          .mitigation({
            mitigation_type: "input-validation",
            present: false,
            location: `between source (L${flow.source.line}) and sink (L${flow.sink.line})`,
            detail: "No URL allowlist or internal IP filtering detected in the data flow path. The user-controlled value reaches the network request without sanitization.",
          })
          .impact({
            impact_type: "data-exfiltration",
            scope: "connected-services",
            exploitability: "moderate",
            scenario: `An attacker supplies a malicious URL targeting internal infrastructure (cloud metadata endpoints, internal APIs, localhost services). The MCP server fetches the attacker-controlled URL, leaking internal network data or enabling port scanning of internal services.`,
          })
          .factor("regex_taint", 0.05, "Regex-based taint analysis confirmed flow but with lower precision than AST analysis")
          .reference({
            id: "CWE-918",
            title: "Server-Side Request Forgery (SSRF)",
            relevance: "User input flowing to an outbound HTTP request without validation matches the SSRF pattern in CWE-918",
          })
          .verification({
            step_type: "inspect-source",
            instruction: `Inspect the source at line ${flow.source.line} to confirm user input originates there, then check line ${flow.sink.line} for the HTTP request. Verify the URL is constructed from the user-controlled value.`,
            target: `source_code:${flow.source.line}-${flow.sink.line}`,
            expected_observation: `User input from ${flow.source.category} is used in a URL request at line ${flow.sink.line} without allowlist validation`,
          })
          .verification({
            step_type: "trace-flow",
            instruction: `Trace the variable from line ${flow.source.line} through any assignments or transformations to the network call at line ${flow.sink.line}. Look for any URL validation, domain allowlist, or private IP blocking along the path.`,
            target: `source_code:${flow.source.line}-${flow.sink.line}`,
            expected_observation: "No sanitization or URL validation between user input source and network request sink",
          })
          .build();
        findings.push({
          rule_id: "C3", severity: "high",
          evidence: `[Taint] ${flow.source.category} → URL request (L${flow.sink.line}). SSRF risk.`,
          remediation: "Validate URLs against an allowlist. Block internal IPs.",
          owasp_category: "MCP07-insecure-config", mitre_technique: "AML.T0054",
          confidence: flow.confidence, metadata: { analysis_type: "taint", evidence_chain: chain },
        });
      }
    }
    return findings;
  },
});

// ─── C6: Error Leakage ────────────────────────────────────────────────────

registerTypedRule({
  id: "C6", name: "Error Leakage",
  analyze(ctx) {
    if (!ctx.source_code || isTestFile(ctx.source_code)) return [];
    const findings: TypedFinding[] = [];
    const patterns = [
      { regex: /(?:res|response)\.(?:json|send|write)\s*\(\s*(?:err|error)(?:\.stack|\.message|\s*\))/gi, desc: "error object in HTTP response" },
      { regex: /(?:stack|stackTrace|stack_trace)\s*[:=]\s*(?:err|error|e)\.stack/gi, desc: "stack trace exposed" },
      { regex: /console\.(?:error|log)\s*\(.*(?:err|error)\.stack/gi, desc: "stack trace in logs (may reach client)" },
    ];
    for (const { regex, desc } of patterns) {
      regex.lastIndex = 0;
      const match = regex.exec(ctx.source_code);
      if (match) {
        const matchLine = lineNum(ctx.source_code!, match.index);
        const chain = new EvidenceChainBuilder()
          .source({
            source_type: "environment",
            location: `line ${matchLine}`,
            observed: match[0].slice(0, 80),
            rationale: "Server-internal error objects contain stack traces, file paths, dependency versions, and environment details. These are sensitive runtime artifacts that should never reach external consumers.",
          })
          .sink({
            sink_type: "credential-exposure",
            location: `line ${matchLine}`,
            observed: desc,
          })
          .mitigation({
            mitigation_type: "sanitizer-function",
            present: false,
            location: `line ${matchLine}`,
            detail: "No error sanitization or generic error mapping found. The raw error object (including stack trace) is sent directly in the response body without filtering sensitive details.",
          })
          .impact({
            impact_type: "data-exfiltration",
            scope: "server-host",
            exploitability: "trivial",
            scenario: `An attacker triggers an error condition and receives the full stack trace in the response. The stack trace reveals internal file paths, dependency versions, database connection details, and server architecture — information used to plan targeted attacks against specific library vulnerabilities or file system layout.`,
          })
          .factor("structural_match", 0.1, "Direct pattern match of error object in response body")
          .reference({
            id: "CWE-209",
            title: "Generation of Error Message Containing Sensitive Information",
            relevance: "Exposing stack traces in HTTP responses matches CWE-209, enabling attackers to gather reconnaissance data about server internals",
          })
          .verification({
            step_type: "inspect-source",
            instruction: `Examine line ${matchLine} to confirm that an error object (err, error, or its .stack/.message property) is passed directly to a response method (res.json, res.send, res.write). Verify no error-sanitization middleware transforms the error before sending.`,
            target: `source_code:${matchLine}`,
            expected_observation: `Raw error object or stack trace sent in response body via ${desc}`,
          })
          .verification({
            step_type: "trace-flow",
            instruction: `Check the surrounding error handler or catch block for any error transformation logic. Look for a global error handler middleware that might sanitize errors before they reach the client. Also check if this code path is reachable in production (not just development mode).`,
            target: `source_code:${matchLine}`,
            expected_observation: "No error sanitization middleware and no environment check gating the detailed error response to development only",
          })
          .build();
        findings.push({
          rule_id: "C6", severity: "medium",
          evidence: `${desc} at line ${matchLine}: "${match[0].slice(0, 80)}".`,
          remediation: "Return generic error messages to clients. Log full errors server-side only.",
          owasp_category: "MCP07-insecure-config", mitre_technique: null,
          confidence: 0.80, metadata: { analysis_type: "structural", evidence_chain: chain },
        });
        break;
      }
    }
    return findings;
  },
});

// ─── C7: Wildcard CORS ────────────────────────────────────────────────────

registerTypedRule({
  id: "C7", name: "Wildcard CORS",
  analyze(ctx) {
    if (!ctx.source_code || isTestFile(ctx.source_code)) return [];
    const findings: TypedFinding[] = [];
    const patterns = [
      { regex: /(?:Access-Control-Allow-Origin|cors)\s*[:({]\s*['"]?\*/gi, desc: "CORS wildcard origin" },
      { regex: /cors\s*\(\s*\)/gi, desc: "CORS with no origin restriction (defaults to *)" },
      { regex: /origin\s*:\s*true/gi, desc: "CORS reflects any origin" },
    ];
    for (const { regex, desc } of patterns) {
      regex.lastIndex = 0;
      const match = regex.exec(ctx.source_code);
      if (match) {
        findings.push({
          rule_id: "C7", severity: "high",
          evidence: `${desc} at line ${lineNum(ctx.source_code, match.index)}: "${match[0].slice(0, 60)}".`,
          remediation: "Set specific allowed origins. Never use '*' with credentials.",
          owasp_category: "MCP07-insecure-config", mitre_technique: null,
          confidence: 0.88, metadata: { analysis_type: "structural" },
        });
        break;
      }
    }
    return findings;
  },
});

// ─── C8: No Auth on Network Interface ─────────────────────────────────────

registerTypedRule({
  id: "C8", name: "No Auth on Network Interface",
  analyze(ctx) {
    if (!ctx.source_code || isTestFile(ctx.source_code)) return [];
    const findings: TypedFinding[] = [];
    const match = /(?:listen|bind|serve)\s*\(\s*(?:\d+|port)\s*,\s*['"]0\.0\.0\.0['"]/i.exec(ctx.source_code);
    if (match) {
      // Check if auth middleware is present nearby
      const hasAuth = /(?:auth|authenticate|verify|passport|jwt|bearer|apiKey|session)/i.test(ctx.source_code);
      if (!hasAuth) {
        findings.push({
          rule_id: "C8", severity: "high",
          evidence: `Listening on 0.0.0.0 at line ${lineNum(ctx.source_code, match.index)} without visible auth middleware.`,
          remediation: "Add authentication middleware. Or bind to 127.0.0.1 if the service is internal-only.",
          owasp_category: "MCP07-insecure-config", mitre_technique: null,
          confidence: 0.75, metadata: { analysis_type: "structural" },
        });
      }
    }
    return findings;
  },
});

// ─── C9: Excessive Filesystem Scope ───────────────────────────────────────

registerTypedRule({
  id: "C9", name: "Excessive Filesystem Scope",
  analyze(ctx) {
    if (!ctx.source_code || isTestFile(ctx.source_code)) return [];
    const findings: TypedFinding[] = [];
    const patterns = [
      { regex: /(?:readdir|readdirSync|glob|walkDir|fs\.read)\s*\(\s*['"]\/['"]/gi, desc: "root directory listing" },
      { regex: /(?:allowedPaths?|basePath|rootDir)\s*[:=]\s*['"]\/['"]/gi, desc: "allowed path set to root" },
      { regex: /(?:chdir|process\.chdir)\s*\(\s*['"]\/['"]/gi, desc: "working directory set to root" },
    ];
    for (const { regex, desc } of patterns) {
      regex.lastIndex = 0;
      const match = regex.exec(ctx.source_code);
      if (match) {
        findings.push({
          rule_id: "C9", severity: "high",
          evidence: `${desc} at line ${lineNum(ctx.source_code, match.index)}: "${match[0].slice(0, 60)}".`,
          remediation: "Restrict filesystem access to a specific directory. Never use '/' as base path.",
          owasp_category: "MCP05-privilege-escalation", mitre_technique: "AML.T0054",
          confidence: 0.85, metadata: { analysis_type: "structural" },
        });
        break;
      }
    }
    return findings;
  },
});

// ─── C11: ReDoS Vulnerability ─────────────────────────────────────────────

registerTypedRule({
  id: "C11", name: "ReDoS Vulnerability",
  analyze(ctx) {
    if (!ctx.source_code || isTestFile(ctx.source_code)) return [];
    const findings: TypedFinding[] = [];

    // Detect dangerous regex patterns
    const patterns = [
      { regex: /new\s+RegExp\s*\(\s*(?!['"`])(\w+)/gi, desc: "RegExp from user input (ReDoS + regex injection)" },
      { regex: /\([\w.+*\\]+\+\)\+/g, desc: "catastrophic backtracking: (a+)+" },
      { regex: /\(\[[\w-]+\]\+\)\+/g, desc: "catastrophic backtracking: ([a-z]+)+" },
      { regex: /(?:\.\*){2,}/g, desc: "nested wildcards" },
    ];

    for (const { regex, desc } of patterns) {
      regex.lastIndex = 0;
      const match = regex.exec(ctx.source_code);
      if (match) {
        findings.push({
          rule_id: "C11", severity: "high",
          evidence: `${desc} at line ${lineNum(ctx.source_code, match.index)}: "${match[0].slice(0, 60)}".`,
          remediation: "Never construct RegExp from user input. Use re2 or regex bounds. Avoid (a+)+ patterns.",
          owasp_category: "MCP07-insecure-config", mitre_technique: null,
          confidence: desc.includes("user input") ? 0.90 : 0.75, metadata: { analysis_type: "structural" },
        });
        break;
      }
    }
    return findings;
  },
});

// ─── C15: Timing Attack on Secret Comparison ──────────────────────────────

registerTypedRule({
  id: "C15", name: "Timing Attack on Secret Comparison",
  analyze(ctx) {
    if (!ctx.source_code || isTestFile(ctx.source_code)) return [];
    const findings: TypedFinding[] = [];

    // Detect === on secret-like variables without timingSafeEqual
    const hasTimingSafe = /(?:timingSafeEqual|compare_digest|constant_time|secure_compare)/i.test(ctx.source_code);
    if (hasTimingSafe) return findings; // Uses safe comparison somewhere

    const patterns = [
      { regex: /(?:token|secret|key|apiKey|api_key|password|hmac|hash|digest)\s*===?\s*(?:req\.|request\.|params|body|header)/gi, desc: "secret compared with === (timing-vulnerable)" },
      { regex: /(?:req\.|request\.|params|body|header)[\w.]*\s*===?\s*(?:token|secret|key|apiKey|api_key|password|hmac)/gi, desc: "request value compared to secret with ===" },
    ];

    for (const { regex, desc } of patterns) {
      regex.lastIndex = 0;
      const match = regex.exec(ctx.source_code);
      if (match) {
        findings.push({
          rule_id: "C15", severity: "high",
          evidence: `${desc} at line ${lineNum(ctx.source_code, match.index)}: "${match[0].slice(0, 80)}".`,
          remediation: "Use crypto.timingSafeEqual() for Node.js or hmac.compare_digest() for Python.",
          owasp_category: "MCP07-insecure-config", mitre_technique: null,
          confidence: 0.85, metadata: { analysis_type: "structural" },
        });
        break;
      }
    }
    return findings;
  },
});
