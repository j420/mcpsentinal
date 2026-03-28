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
        findings.push({
          rule_id: "C3", severity: "high",
          evidence: `[AST taint] ${flow.source.category} "${flow.source.expression}" (L${flow.source.line}) → HTTP request (L${flow.sink.line}). SSRF risk.`,
          remediation: "Validate URLs against an allowlist. Block private/internal IPs (10.x, 172.16.x, 192.168.x, 169.254.x).",
          owasp_category: "MCP07-insecure-config", mitre_technique: "AML.T0054",
          confidence: flow.confidence, metadata: { analysis_type: "ast_taint" },
        });
      }
    } catch { /* fall through */ }

    if (findings.length === 0) {
      const flows = analyzeTaint(ctx.source_code);
      for (const flow of flows.filter(f => f.sink.category === "url_request" && !f.sanitized)) {
        findings.push({
          rule_id: "C3", severity: "high",
          evidence: `[Taint] ${flow.source.category} → URL request (L${flow.sink.line}). SSRF risk.`,
          remediation: "Validate URLs against an allowlist. Block internal IPs.",
          owasp_category: "MCP07-insecure-config", mitre_technique: "AML.T0054",
          confidence: flow.confidence, metadata: { analysis_type: "taint" },
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
        findings.push({
          rule_id: "C6", severity: "medium",
          evidence: `${desc} at line ${lineNum(ctx.source_code, match.index)}: "${match[0].slice(0, 80)}".`,
          remediation: "Return generic error messages to clients. Log full errors server-side only.",
          owasp_category: "MCP07-insecure-config", mitre_technique: null,
          confidence: 0.80, metadata: { analysis_type: "structural" },
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
