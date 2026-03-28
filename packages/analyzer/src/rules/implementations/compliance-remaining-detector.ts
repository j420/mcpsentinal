/**
 * Compliance Remaining — K1, K4, K6, K7, K11-K20 (minus those already migrated)
 * Plus remaining stragglers: L3, L8, L10, L14, L15, M2, M4, M5, M7, M8,
 * N1-N3, N7, N8, N10, O4, O6, O8, O10, P8-P10, Q10, Q12, Q14, Q15
 */

import type { TypedRule, TypedFinding } from "../base.js";
import { registerTypedRule } from "../base.js";
import type { AnalysisContext } from "../../engine.js";

function isTestFile(s: string) { return /(?:__tests?__|\.(?:test|spec)\.)/.test(s); }
function lineNum(s: string, i: number) { return s.substring(0, i).split("\n").length; }

type RCfg = {
  id: string; name: string;
  source: "code" | "tools" | "metadata" | "deps" | "conn";
  patterns: Array<{ regex: RegExp; desc: string }>;
  severity: "critical" | "high" | "medium" | "low";
  owasp: string; mitre: string | null; remediation: string;
  confidence: number;
  excludePatterns?: RegExp[];
};

function buildRule(cfg: RCfg): TypedRule {
  return {
    id: cfg.id, name: cfg.name,
    analyze(ctx) {
      if (cfg.source === "code") {
        if (!ctx.source_code || isTestFile(ctx.source_code)) return [];
        const findings: TypedFinding[] = [];
        for (const { regex, desc } of cfg.patterns) {
          regex.lastIndex = 0;
          const match = regex.exec(ctx.source_code);
          if (match) {
            const line = lineNum(ctx.source_code, match.index);
            const lineText = ctx.source_code.split("\n")[line - 1] || "";
            if (cfg.excludePatterns?.some(e => e.test(lineText))) continue;
            findings.push({
              rule_id: cfg.id, severity: cfg.severity,
              evidence: `${desc} at line ${line}: "${match[0].slice(0, 80)}".`,
              remediation: cfg.remediation,
              owasp_category: cfg.owasp as any, mitre_technique: cfg.mitre,
              confidence: cfg.confidence, metadata: { analysis_type: "structural", line },
            });
            break;
          }
        }
        return findings;
      }
      if (cfg.source === "tools") {
        const findings: TypedFinding[] = [];
        for (const tool of ctx.tools) {
          const text = `${tool.name} ${tool.description || ""}`;
          for (const { regex, desc } of cfg.patterns) {
            regex.lastIndex = 0;
            if (regex.test(text)) {
              findings.push({
                rule_id: cfg.id, severity: cfg.severity,
                evidence: `Tool "${tool.name}": ${desc}.`,
                remediation: cfg.remediation,
                owasp_category: cfg.owasp as any, mitre_technique: cfg.mitre,
                confidence: cfg.confidence, metadata: { tool_name: tool.name },
              });
              break;
            }
          }
        }
        return findings;
      }
      return [];
    },
  };
}

// ─── K-remaining ───────────────────────────────────────────────────────────

const K_RULES: RCfg[] = [
  { id: "K1", name: "Absent Structured Logging", source: "code",
    patterns: [
      { regex: /console\.(?:log|warn|error)\s*\(\s*['"`](?:request|handling|processing)/gi, desc: "console.log for request handling instead of structured logger" },
      { regex: /logging\.disable\s*\(/gi, desc: "logging disabled" },
    ],
    severity: "high", owasp: "MCP09-logging-monitoring", mitre: null,
    remediation: "Use structured logging (pino, winston) with correlation IDs. Never use console.log for request handling.",
    confidence: 0.75, excludePatterns: [/pino|winston|bunyan|log4js|structured/i],
  },
  { id: "K4", name: "Missing Human Confirmation for Destructive Ops", source: "code",
    patterns: [
      { regex: /(?:delete|remove|drop|truncate|destroy|purge|wipe)(?:All|Many|Bulk|Batch)?\s*\([^)]*\)(?!.*(?:confirm|prompt|approve|ask|verify))/gi, desc: "destructive operation without confirmation" },
    ],
    severity: "high", owasp: "ASI09-human-oversight-bypass", mitre: null,
    remediation: "Add user confirmation before destructive operations. Implement a confirmation dialog or approval workflow.",
    confidence: 0.72, excludePatterns: [/test|mock|fixture|confirm|approve/i],
  },
  { id: "K6", name: "Overly Broad OAuth Scopes", source: "code",
    patterns: [
      { regex: /scope\s*[:=]\s*['"](?:admin|root|all|\*|read:all|write:all)/gi, desc: "overly broad OAuth scope" },
    ],
    severity: "high", owasp: "ASI03-identity-privilege-abuse", mitre: null,
    remediation: "Use minimal OAuth scopes. Request only the permissions actually needed.",
    confidence: 0.85,
  },
  { id: "K7", name: "Long-Lived Tokens Without Rotation", source: "code",
    patterns: [
      { regex: /(?:expiresIn|expires_in|maxAge|max_age)\s*[:=]\s*['"]?(?:365d|8760h|31536000|\d{8,})/gi, desc: "token with >1 year expiry" },
      { regex: /(?:token|jwt).*(?:never\s+expire|no\s+expir|immortal)/gi, desc: "non-expiring token" },
    ],
    severity: "high", owasp: "ASI03-identity-privilege-abuse", mitre: null,
    remediation: "Set token expiry to <24h for access tokens, <30d for refresh tokens. Implement token rotation.",
    confidence: 0.82,
  },
  { id: "K11", name: "Missing Server Integrity Verification", source: "code",
    patterns: [
      { regex: /(?:connect|load|register)\s*(?:mcp|server|tool)(?!.*(?:verify|validate|checksum|hash|sign))/gi, desc: "MCP server loaded without integrity verification" },
    ],
    severity: "high", owasp: "MCP10-supply-chain", mitre: null,
    remediation: "Verify server integrity via checksums, signatures, or registry lookup before connecting.",
    confidence: 0.68,
  },
  { id: "K12", name: "Executable Content in Tool Response", source: "code",
    patterns: [
      { regex: /(?:return|respond|output|send).*(?:eval|exec|Function|import|require)\s*\(/gi, desc: "executable code in tool response" },
      { regex: /(?:content|result|response).*(?:<script|javascript:|on\w+=)/gi, desc: "HTML/JS in tool response" },
    ],
    severity: "critical", owasp: "MCP03-command-injection", mitre: "AML.T0054",
    remediation: "Tool responses must not contain executable code. Sanitize all output.",
    confidence: 0.80,
  },
  { id: "K13", name: "Unsanitized Tool Output", source: "code",
    patterns: [
      { regex: /(?:return|respond|send)\s*\(\s*(?:raw|unsanitized|unescaped)/gi, desc: "explicitly unsanitized output" },
      { regex: /(?:innerHTML|dangerouslySetInnerHTML|v-html)\s*[:=]/gi, desc: "unsafe HTML rendering" },
    ],
    severity: "high", owasp: "MCP03-command-injection", mitre: null,
    remediation: "Sanitize all tool output. Use text content, not HTML. Escape special characters.",
    confidence: 0.78,
  },
  { id: "K14", name: "Agent Credential Propagation via Shared State", source: "code",
    patterns: [
      { regex: /(?:shared|global|common)\s*(?:state|store|memory|context).*(?:token|credential|secret|api_key|password)/gi, desc: "credentials in shared state" },
      { regex: /(?:token|credential|secret|api_key).*(?:shared|global|common)\s*(?:state|store|memory)/gi, desc: "credentials stored in shared state" },
    ],
    severity: "critical", owasp: "ASI03-identity-privilege-abuse", mitre: "AML.T0054",
    remediation: "Never store credentials in shared state. Use per-agent credential stores with proper isolation.",
    confidence: 0.80,
  },
  { id: "K15", name: "Multi-Agent Collusion Preconditions", source: "code",
    patterns: [
      { regex: /(?:agent|worker)\s*(?:pool|group|cluster).*(?:share|common|mutual)\s*(?:data|state|memory|context)/gi, desc: "agents sharing state (collusion enabler)" },
    ],
    severity: "high", owasp: "ASI07-insecure-inter-agent-comms", mitre: null,
    remediation: "Isolate agent state. Use message passing instead of shared memory between agents.",
    confidence: 0.72,
  },
  { id: "K16", name: "Unbounded Recursion", source: "code",
    patterns: [
      { regex: /(?:recursive|recurse|self[_\s]?call)(?!.*(?:depth|limit|max|bound|guard))/gi, desc: "recursion without depth limit" },
      { regex: /(?:while\s*\(\s*true|for\s*\(\s*;\s*;\s*\))(?!.*(?:break|return|limit|max|timeout))/gi, desc: "infinite loop without exit condition" },
    ],
    severity: "high", owasp: "MCP07-insecure-config", mitre: null,
    remediation: "Add recursion depth limits. Add timeout/circuit breakers to all loops.",
    confidence: 0.72,
  },
  { id: "K17", name: "Missing Timeout or Circuit Breaker", source: "code",
    patterns: [
      { regex: /(?:fetch|axios|request|http\.get)\s*\([^)]*\)(?!.*(?:timeout|signal|AbortController|deadline))/gi, desc: "HTTP request without timeout" },
    ],
    severity: "medium", owasp: "MCP07-insecure-config", mitre: null,
    remediation: "Add timeouts to all HTTP requests. Use AbortController for fetch. Set timeout option for axios.",
    confidence: 0.68, excludePatterns: [/timeout|signal|abort/i],
  },
  { id: "K18", name: "Cross-Trust-Boundary Data Flow", source: "code",
    patterns: [
      { regex: /(?:internal|private|sensitive|secret).*(?:return|respond|send|output|expose).*(?:external|public|client|response)/gi, desc: "sensitive data crossing trust boundary" },
    ],
    severity: "high", owasp: "MCP04-data-exfiltration", mitre: null,
    remediation: "Classify data sensitivity. Prevent sensitive data from crossing trust boundaries without redaction.",
    confidence: 0.72,
  },
  { id: "K19", name: "Missing Runtime Sandbox", source: "code",
    patterns: [
      { regex: /(?:docker|container).*(?:--privileged|--cap-add|--security-opt.*no-new-privileges.*false)/gi, desc: "container security disabled" },
      { regex: /(?:seccomp|apparmor|selinux).*(?:unconfined|disabled|off|false)/gi, desc: "sandbox enforcement disabled" },
    ],
    severity: "high", owasp: "MCP07-insecure-config", mitre: null,
    remediation: "Enable container sandboxing (seccomp, AppArmor). Never disable security profiles.",
    confidence: 0.82,
  },
  { id: "K20", name: "Insufficient Audit Context", source: "code",
    patterns: [
      { regex: /console\.log\s*\(\s*['"](?:request|handling|processing|received)/gi, desc: "console.log for audit events instead of structured logging" },
      { regex: /logger\.(?:info|warn|error)\s*\(\s*['"][^'"]*['"]\s*\)(?!\s*,)/gi, desc: "logger with string-only (no structured context)" },
    ],
    severity: "medium", owasp: "MCP09-logging-monitoring", mitre: null,
    remediation: "Use structured logging with request ID, user ID, action, and timestamp in every log entry.",
    confidence: 0.70, excludePatterns: [/pino|winston|structured|correlationId|requestId/i],
  },
];

// ─── L/M/N/O/P/Q remaining stragglers ─────────────────────────────────────

const STRAGGLER_RULES: RCfg[] = [
  { id: "L3", name: "Dockerfile Base Image Risk", source: "code",
    patterns: [
      { regex: /^FROM\s+(?!scratch)[\w./-]+:(?:latest|stable|lts)\s/gim, desc: "mutable base image tag (latest/stable/lts)" },
      { regex: /^FROM\s+(?!scratch)[\w./-]+\s*$/gim, desc: "base image without tag (defaults to latest)" },
    ],
    severity: "high", owasp: "MCP10-supply-chain", mitre: "AML.T0017",
    remediation: "Pin base images to SHA256 digests: FROM image@sha256:abc123...",
    confidence: 0.82,
  },
  { id: "L8", name: "Version Rollback Attack", source: "code",
    patterns: [
      { regex: /(?:overrides|resolutions|pnpm\.overrides).*[:=].*(?:0\.|1\.0\.|<=|<\d)/gi, desc: "dependency override to old version" },
      { regex: /(?:npm\s+install|pip\s+install).*(?:@0\.|@1\.0\.|==0\.|==1\.0\.).*(?:mcp|server|sdk)/gi, desc: "installing old version of MCP package" },
    ],
    severity: "high", owasp: "MCP10-supply-chain", mitre: "AML.T0017",
    remediation: "Don't override dependencies to old versions. Use automated updates (Dependabot, Renovate).",
    confidence: 0.78,
  },
  { id: "L10", name: "Registry Metadata Spoofing", source: "code",
    patterns: [
      { regex: /(?:author|publisher|organization).*[:=].*(?:Anthropic|OpenAI|Google|Microsoft)/gi, desc: "false vendor attribution in metadata" },
      { regex: /(?:official|verified|certified).*(?:by|from).*(?:Anthropic|OpenAI|Google|Microsoft)/gi, desc: "false official certification" },
    ],
    severity: "high", owasp: "MCP10-supply-chain", mitre: "AML.T0017",
    remediation: "Don't impersonate official vendors in package metadata.",
    confidence: 0.82,
  },
  { id: "L15", name: "Update Notification Spoofing", source: "code",
    patterns: [
      { regex: /(?:update|upgrade)\s+(?:available|required|needed).*(?:npm\s+install|pip\s+install|npx)/gi, desc: "fake update notification with install command" },
    ],
    severity: "high", owasp: "MCP10-supply-chain", mitre: "AML.T0017",
    remediation: "Don't display fake update notifications. Updates should come from official package managers.",
    confidence: 0.78,
  },
  { id: "M2", name: "Prompt Leaking via Tool Response", source: "code",
    patterns: [
      { regex: /(?:system_prompt|system_message|initial_instructions).*(?:include|append|concat|add).*(?:response|output|result)/gi, desc: "system prompt included in output" },
    ],
    severity: "high", owasp: "MCP04-data-exfiltration", mitre: "AML.T0057",
    remediation: "Never include system prompts in tool responses. Filter all output.",
    confidence: 0.78,
  },
  { id: "M4", name: "Tool Squatting", source: "tools",
    patterns: [
      { regex: /(?:official|verified|authentic|genuine)\s+(?:version|implementation)/i, desc: "false authenticity claim" },
    ],
    severity: "high", owasp: "MCP02-tool-poisoning", mitre: "AML.T0054",
    remediation: "Don't claim to be an official/verified implementation. Let registries handle verification.",
    confidence: 0.78,
  },
  { id: "M5", name: "Context Window Flooding", source: "tools",
    patterns: [
      { regex: /(?:detailed|verbose|comprehensive|extensive|complete)\s+(?:output|response|result|data)/i, desc: "promises verbose output (context flooding risk)" },
    ],
    severity: "high", owasp: "MCP01-prompt-injection", mitre: null,
    remediation: "Tool responses should be concise. Offer pagination for large data sets.",
    confidence: 0.60,
  },
  { id: "M7", name: "Multi-Turn State Injection", source: "code",
    patterns: [
      { regex: /(?:conversation|chat|history|context).*(?:inject|insert|prepend|append|modify)/gi, desc: "conversation history manipulation" },
    ],
    severity: "high", owasp: "MCP01-prompt-injection", mitre: "AML.T0058",
    remediation: "Never modify conversation history from tool code. History should be managed by the AI client.",
    confidence: 0.78,
  },
  { id: "M8", name: "Encoding Attack on Tool Input", source: "code",
    patterns: [
      { regex: /(?:decode|unescape|fromCharCode|String\.raw).*(?:tool|input|param|arg)(?!.*(?:validate|sanitize))/gi, desc: "decoded tool input without validation" },
    ],
    severity: "high", owasp: "MCP03-command-injection", mitre: "AML.T0054",
    remediation: "Validate tool inputs after decoding. Apply allowlists to decoded values.",
    confidence: 0.72,
  },
  { id: "N1", name: "JSON-RPC Batch Request Abuse", source: "code",
    patterns: [
      { regex: /(?:batch|array).*(?:request|rpc|method)(?!.*(?:limit|max|throttle|rate))/gi, desc: "batch requests without limits" },
    ],
    severity: "high", owasp: "MCP07-insecure-config", mitre: null,
    remediation: "Limit batch request size. Add rate limiting per batch.",
    confidence: 0.68,
  },
  { id: "N2", name: "Notification Flooding", source: "code",
    patterns: [
      { regex: /(?:notify|notification|emit|push).*(?:loop|interval|setInterval|while)(?!.*(?:throttle|debounce|limit|rate))/gi, desc: "notifications in loop without throttle" },
    ],
    severity: "high", owasp: "MCP07-insecure-config", mitre: null,
    remediation: "Throttle notifications. Add rate limits and debouncing.",
    confidence: 0.72,
  },
  { id: "N3", name: "Progress Token Spoofing", source: "code",
    patterns: [
      { regex: /(?:progress|progressToken).*(?:fake|spoof|forge|arbitrary|random)/gi, desc: "progress token manipulation" },
    ],
    severity: "high", owasp: "MCP07-insecure-config", mitre: null,
    remediation: "Validate progress tokens. Use cryptographic tokens, not sequential IDs.",
    confidence: 0.72,
  },
  { id: "N7", name: "Initialization Race Condition", source: "code",
    patterns: [
      { regex: /(?:initialize|init).*(?:parallel|concurrent|race|promise\.all)(?!.*(?:lock|mutex|semaphore|await))/gi, desc: "parallel initialization without synchronization" },
    ],
    severity: "high", owasp: "MCP07-insecure-config", mitre: null,
    remediation: "Serialize initialization. Use locks/mutexes for concurrent init attempts.",
    confidence: 0.68,
  },
  { id: "N8", name: "Ping Abuse for Side Channels", source: "code",
    patterns: [
      { regex: /(?:ping|heartbeat|keepalive).*(?:data|payload|content|message)(?!.*(?:empty|null|void))/gi, desc: "data in ping/heartbeat messages" },
    ],
    severity: "high", owasp: "MCP07-insecure-config", mitre: null,
    remediation: "Ping messages should be empty or contain only timestamps. Never include data.",
    confidence: 0.68,
  },
  { id: "N10", name: "Cancellation Token Injection", source: "code",
    patterns: [
      { regex: /(?:cancel|abort).*(?:token|id)\s*[:=]\s*(?:req\.|request\.|params|body|user)/gi, desc: "cancellation token from user input" },
    ],
    severity: "high", owasp: "MCP07-insecure-config", mitre: null,
    remediation: "Generate cancellation tokens server-side. Never accept them from user input.",
    confidence: 0.78,
  },
  { id: "O4", name: "Timing-Based Data Inference", source: "code",
    patterns: [
      { regex: /(?:setTimeout|delay|sleep|wait)\s*\([^)]*(?:if|switch|condition|result|data)/gi, desc: "conditional delay (timing side channel)" },
    ],
    severity: "high", owasp: "MCP04-data-exfiltration", mitre: "AML.T0057",
    remediation: "Use constant-time operations for sensitive data. Add random jitter to response times.",
    confidence: 0.68,
  },
  { id: "O6", name: "Clipboard / Pasteboard Access", source: "code",
    patterns: [
      { regex: /(?:clipboard|pasteboard|pbcopy|pbpaste|xclip|xsel).*(?:read|write|get|set|copy|paste)/gi, desc: "clipboard access (data leakage vector)" },
    ],
    severity: "high", owasp: "MCP04-data-exfiltration", mitre: "AML.T0057",
    remediation: "MCP servers should not access the clipboard. Remove clipboard read/write operations.",
    confidence: 0.82,
  },
  { id: "O8", name: "Screenshot / Screen Capture", source: "code",
    patterns: [
      { regex: /(?:screenshot|screen.?capture|screen.?grab|captureScreen|desktopCapturer)/gi, desc: "screen capture capability" },
    ],
    severity: "high", owasp: "MCP04-data-exfiltration", mitre: "AML.T0057",
    remediation: "MCP servers should not capture screenshots. This is a significant data exfiltration vector.",
    confidence: 0.85,
  },
  { id: "O10", name: "Keylogging / Input Monitoring", source: "code",
    patterns: [
      { regex: /(?:keylog|keypress|keydown|keyup|input.?monitor|keyboard.?hook)/gi, desc: "keyboard/input monitoring" },
    ],
    severity: "high", owasp: "MCP04-data-exfiltration", mitre: "AML.T0057",
    remediation: "MCP servers must not monitor keyboard input. Remove all input capture code.",
    confidence: 0.90,
  },
  { id: "P8", name: "ECB Mode / Static IV", source: "code",
    patterns: [
      { regex: /(?:ECB|ecb)\s*(?:mode|cipher|encrypt)/gi, desc: "ECB mode (pattern-preserving encryption)" },
      { regex: /(?:iv|IV|nonce)\s*[:=]\s*(?:['"](?:0{8,}|1{8,}|abc|000)|Buffer\.alloc\(\d+\))/gi, desc: "static/zero IV" },
      { regex: /Math\.random\s*\(\s*\).*(?:key|secret|iv|nonce|salt|token)/gi, desc: "Math.random for cryptographic purpose" },
    ],
    severity: "high", owasp: "MCP07-insecure-config", mitre: null,
    remediation: "Use CBC/GCM mode. Generate random IVs with crypto.randomBytes(). Never use Math.random() for crypto.",
    confidence: 0.85,
  },
  { id: "P9", name: "Excessive Container Resource Limits", source: "code",
    patterns: [
      { regex: /(?:memory|mem_limit|memoryLimit)\s*[:=]\s*['"]?(?:\d{5,}|unlimited|0)\s*(?:Mi|Gi|MB|GB)?/gi, desc: "excessive memory allocation" },
      { regex: /(?:cpu|cpuLimit)\s*[:=]\s*['"]?(?:unlimited|0)\s*$/gim, desc: "unlimited CPU allocation" },
    ],
    severity: "high", owasp: "MCP07-insecure-config", mitre: null,
    remediation: "Set reasonable resource limits for containers. Unlimited resources enable DoS attacks.",
    confidence: 0.72,
  },
  { id: "P10", name: "Network Host Mode", source: "code",
    patterns: [
      { regex: /(?:network_mode|networkMode)\s*[:=]\s*['"]?host/gi, desc: "container in host network mode" },
      { regex: /--net(?:work)?[=\s]+host/gi, desc: "Docker host network flag" },
    ],
    severity: "high", owasp: "MCP07-insecure-config", mitre: null,
    remediation: "Use bridge or overlay networks. Host network mode exposes all host ports to the container.",
    confidence: 0.88,
  },
  { id: "Q10", name: "Agent Memory Poisoning", source: "tools",
    patterns: [
      { regex: /(?:memory|remember|store|persist|save).*(?:instruction|directive|rule|policy|behavior)/i, desc: "tool that stores behavioral instructions in agent memory" },
    ],
    severity: "high", owasp: "ASI06-memory-context-poisoning", mitre: "AML.T0058",
    remediation: "Agent memory should store facts, not behavioral instructions. Validate all stored content.",
    confidence: 0.72,
  },
  { id: "Q12", name: "Browser Extension ↔ MCP Bridge", source: "code",
    patterns: [
      { regex: /(?:chrome|browser)\.runtime\.(?:sendMessage|connect|sendNativeMessage).*(?:mcp|tool|server)/gi, desc: "browser extension to MCP bridge" },
    ],
    severity: "high", owasp: "MCP05-privilege-escalation", mitre: null,
    remediation: "Don't bridge browser extension APIs to MCP servers without sandboxing and permission checks.",
    confidence: 0.78,
  },
  { id: "Q14", name: "Cross-Language Serialization Mismatch", source: "code",
    patterns: [
      { regex: /(?:serialize|marshal|encode).*(?:python|ruby|java|php).*(?:deserialize|unmarshal|decode).*(?:javascript|node|typescript)/gi, desc: "cross-language serialization without type validation" },
    ],
    severity: "high", owasp: "MCP03-command-injection", mitre: "AML.T0054",
    remediation: "Use language-neutral serialization (JSON, protobuf). Validate types after deserialization.",
    confidence: 0.72,
  },
  { id: "Q15", name: "Agentic Workflow Persistence Hijacking", source: "code",
    patterns: [
      { regex: /(?:checkpoint|snapshot|persist|save)\s*(?:workflow|state|progress).*(?:file|disk|db|store)(?!.*(?:encrypt|sign|verify|hash))/gi, desc: "workflow state persisted without integrity protection" },
    ],
    severity: "high", owasp: "MCP07-insecure-config", mitre: null,
    remediation: "Sign or encrypt persisted workflow state. Verify integrity on resume.",
    confidence: 0.72,
  },
];

// Register all
for (const cfg of [...K_RULES, ...STRAGGLER_RULES]) {
  registerTypedRule(buildRule(cfg));
}
