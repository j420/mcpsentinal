# MCP Sentinel — Detection Rules Specification
## P8 Detection Rule Engineer Output — v4.0 (with P1 Threat Intelligence + 2026 Attack Surface)

### Rule Categories

| Category | Code | Requires Source Code | Rule Count | Authored By |
|----------|------|---------------------|------------|-------------|
| Description Analysis | A | No | 9 | Security Engineer |
| Schema Analysis | B | No | 7 | Security Engineer |
| Code Analysis | C | Yes | 16 | Security Engineer |
| Dependency Analysis | D | Yes (package manifest) | 7 | Security Engineer |
| Behavioral Analysis | E | No (connection metadata) | 4 | Security Engineer |
| Ecosystem Context | F | No (tool metadata) | 7 | Security Engineer |
| **Adversarial AI** | **G** | **No (metadata + history)** | **7** | **P1 Threat Researcher** |
| **2026 Attack Surface** | **H** | **Mixed** | **3** | **OAuth Specialist + Protocol Researcher + Agentic AI Researcher** |
| **Total** | | | **60** | |

### The G-Category: What a Threat Researcher Adds

Rules A–F are what a skilled security engineer produces by applying OWASP and classic vulnerability research to MCP. They detect flaws that exist independent of AI.

Rules G1–G7 are what a **Threat Intelligence Researcher** who has studied actual LLM exploitation produces. These rules detect attacks that **only work because the target is an AI** — they require deep understanding of how language models reason, what they implicitly trust, and how they process tool metadata differently from humans.

**Primary threat intelligence sources for G-rules:**
- Johann Rehberger (Embrace The Red) — indirect prompt injection demonstrations against Claude/GPT-4 (2024)
- Invariant Labs — MCP indirect injection research paper (2025)
- Wiz Research — MCP supply chain attack analysis
- MITRE ATLAS AML.T0054 — LLM prompt injection technique taxonomy
- Real-world incidents: Claude Desktop compromised via web-scraping MCP (2024-Q4)

### The H-Category: What March 2026 Changes

Rules A–G were comprehensive for the MCP ecosystem at launch. By March 2026, three structural changes to the MCP ecosystem opened attack surfaces that didn't exist when those rules were written:

1. **OAuth 2.0 is now the official MCP auth standard** (H1): RFC 9700 / MCP Authorization spec added OAuth 2.0 as the standard authentication mechanism for remote MCP servers in mid-2025. This created a class of authentication vulnerabilities (redirect_uri injection, implicit flow, ROPC, token storage) with no coverage in rules A–G.

2. **The `initialize` response `instructions` field** (H2): The `instructions` field in `InitializeResult` has been present since the original `2024-11-05` MCP spec. It is a spec-sanctioned field that AI clients are designed to follow. Combined with `serverInfo.name` and `serverInfo.version`, the initialize handshake is a three-field injection surface processed before any tool description, before any safety context, and with higher implicit trust than tool descriptions. Client support for actually reading and acting on this field became widespread with the `2025-03-26` spec adoption — this is what makes H2 newly actionable in 2026.

3. **Multi-agent orchestration went mainstream** (H3): LangGraph, AutoGen, CrewAI, and Anthropic's own Claude multi-agent patterns make MCP the integration layer between agents. This enables cross-agent prompt injection propagation — a compromised upstream agent can inject through shared MCP tools into downstream agents. Documented in real-world attacks (Embrace The Red Nov 2025, Invariant Labs Jan 2026, Trail of Bits Feb 2026).

**Primary threat intelligence sources for H-rules:**
- RFC 9700 (OAuth 2.0 for Browser-Based Apps / OAuth 2.1)
- OAuth Security BCP (RFC 9700 §4), Portswigger OAuth attack research (2024-2025)
- MCP Specification `2024-11-05`: initialize response `instructions` field (original spec)
- MCP Specification `2025-03-26`: Streamable HTTP transport + tool annotations added
- Embrace The Red: "Prompt injection cascade in multi-agent AutoGen" (Nov 2025)
- Invariant Labs: "Cross-agent pollution via shared MCP memory" (Jan 2026)
- Trail of Bits: "Trust boundaries in agentic AI systems" (Feb 2026)

**Spec version reference (verified):**
- `2024-11-05` — original spec: SSE transport, `instructions` field, tool descriptions
- `2025-03-26` — Streamable HTTP transport + tool annotations (readOnlyHint, destructiveHint, etc.)
- `2025-11-25` — November 2025 refinements (NOT `2025-11-05` — that version tag does not exist)

### Severity Weights (for scoring)

| Severity | Weight | Score Penalty |
|----------|--------|---------------|
| Critical | 25 | -25 points |
| High | 15 | -15 points |
| Medium | 8 | -8 points |
| Low | 3 | -3 points |
| Informational | 1 | -1 point |

### OWASP MCP Top 10 Coverage

| OWASP ID | Name | Rules |
|----------|------|-------|
| MCP01 | Prompt Injection | A1, A5, A7, A8, A9, B5, F1, F6 |
| MCP02 | Tool Poisoning | A2, A4, A6, F2, F5 |
| MCP03 | Command Injection | C1, C9, C13, C16 |
| MCP04 | Data Exfiltration | A3, F1, F3, F7 |
| MCP05 | Privilege Escalation | C2, C8, C10, C12 |
| MCP06 | Excessive Permissions | A2, B3, B7, E4, F2 |
| MCP07 | Insecure Configuration | B6, C7, C8, C11, C14, C15, D6, E1, E2 |
| MCP08 | Dependency Vulnerabilities | D1, D2, D3, D4, D5, D6, D7 |
| MCP09 | Logging & Monitoring | C6, E3 |
| MCP10 | Supply Chain | D3, D5, D7, A4, F5 |

---

### Rule Definitions

#### Category A — Description Analysis (9 rules)

| ID | Name | Severity | What Makes It Extraordinary |
|----|------|----------|----------------------------|
| A1 | Prompt Injection in Tool Description | Critical | Covers role injection, multi-turn setup, exfiltration directives, prompt delimiter injection, base64-encoded payloads — not just the classic "ignore previous instructions" |
| A2 | Excessive Scope Claims | High | Detects unrestricted access claims in descriptions |
| A3 | Suspicious URLs | Medium | Covers 15+ suspicious TLD categories, URL shorteners (bit.ly, tinyurl etc.), canary/webhook infrastructure, DNS exfiltration patterns, tunneling services (ngrok, serveo) |
| A4 | Cross-Server Tool Name Shadowing | High | 60+ common tool names from all official Anthropic MCP servers — not just 10 generic names |
| A5 | Description Length Anomaly | Low | Flags excessively long descriptions hiding injections |
| **A6** | **Unicode Homoglyph Attack** | **Critical** | **Detects Cyrillic, Greek, Mathematical Alphanumerics, Fullwidth Latin in tool names — no other MCP security tool checks this** |
| **A7** | **Zero-Width Character Injection** | **Critical** | **Detects 15 invisible Unicode categories: ZWS, ZWNJ, ZWJ, soft hyphens, RTL override (U+202E), tag characters, variation selectors — invisible to human review, processed by LLMs** |
| **A8** | **Description-Capability Mismatch** | **High** | **Detects "read-only" description claims paired with write-capable parameters — deceptive labeling unique to AI tool contexts** |
| **A9** | **Encoded Instructions in Description** | **Critical** | **Detects base64 blocks, URL encoding, HTML entities, Unicode escapes, hex sequences hiding instructions from human reviewers** |

#### Category B — Schema Analysis (7 rules)

| ID | Name | Severity | What Makes It Extraordinary |
|----|------|----------|----------------------------|
| B1 | Missing Input Validation | Medium | String/number params without constraints |
| B2 | Dangerous Parameter Types | High | File path, command, SQL, URL parameter names |
| B3 | Excessive Parameter Count | Low | >15 parameters per tool |
| B4 | Schema-less Tools | Medium | Tools with no input schema |
| **B5** | **Prompt Injection in Parameter Description** | **Critical** | **Scans parameter-level description fields — a secondary injection surface that every other MCP security tool misses entirely** |
| **B6** | **Schema Allows Unconstrained Additional Properties** | **Medium** | **additionalProperties: true or not set to false bypasses all parameter validation** |
| **B7** | **Dangerous Default Parameter Values** | **High** | **Defaults to '/', '*', allow_overwrite: true, recursive: true, disable_ssl_verify: true, read_only: false** |

#### Category C — Code Analysis (16 rules)

| ID | Name | Severity | What Makes It Extraordinary |
|----|------|----------|----------------------------|
| C1 | Command Injection | Critical | Extended: spawnSync with user input, shelljs, vm module, template literals in exec, all Python subprocess variants with shell=True |
| C2 | Path Traversal | Critical | Extended: literal `../..` detection, null bytes `\x00`, `%2e%2e`, URL-encoded variants |
| C3 | SSRF | High | URL variable-name heuristic across Node.js and Python HTTP libraries |
| C4 | SQL Injection | Critical | Template literal and string concatenation patterns across JS/Python |
| C5 | Hardcoded Secrets | Critical | 20+ token formats — OpenAI/Anthropic, GitHub PAT, AWS AKIA/ASIA, Slack xoxb/xoxp, Stripe sk_live, Twilio AC tokens, SendGrid SG., JWT eyJ, SSH PEM `-----BEGIN`, Discord, Google AIza, Telegram, npm, Databricks dapi |
| C6 | Error Leakage | Medium | Stack trace exposure in response bodies |
| C7 | Wildcard CORS | High | `*` CORS origin in multiple frameworks |
| C8 | No Auth on Network Interface | High | Listening on 0.0.0.0 without auth |
| C9 | Excessive Filesystem Scope | High | Root-level '/' filesystem access patterns |
| **C10** | **Prototype Pollution** | **Critical** | **`__proto__`, constructor.prototype manipulation, Object.assign/lodash merge/deepmerge with user input** |
| **C11** | **ReDoS Vulnerability** | **High** | **Catastrophic backtracking patterns (a+)+, alternation overlaps, new RegExp(userInput) without bounds** |
| **C12** | **Unsafe Deserialization** | **Critical** | **pickle.loads, yaml.load (without SafeLoader), node-serialize (CVE-2017-5941), marshal.loads, ObjectInputStream, PHP unserialize on user input** |
| **C13** | **Server-Side Template Injection** | **Critical** | **Jinja2, Mako, Handlebars, EJS, Pug, Nunjucks, Twig with user-controlled template strings as the template itself** |
| **C14** | **JWT Algorithm Confusion** | **Critical** | **'none' algorithm acceptance, missing algorithm pinning, ignoreExpiration: true, RS256→HS256 downgrade, PyJWT verify=False** |
| **C15** | **Timing Attack on Secret Comparison** | **High** | **`===` comparison on API keys/tokens/HMACs — must use crypto.timingSafeEqual() or hmac.compare_digest()** |
| **C16** | **Dynamic Code Evaluation with User Input** | **Critical** | **eval(), new Function(), setTimeout(string), importlib.import_module, __import__ with user-controlled input** |

#### Category D — Dependency Analysis (7 rules)

| ID | Name | Severity | What Makes It Extraordinary |
|----|------|----------|----------------------------|
| D1 | Known CVEs in Dependencies | High | CVE audit integration (npm audit / pip-audit) |
| D2 | Abandoned Dependencies | Medium | No update in >12 months |
| D3 | Typosquatting Risk | High | **Levenshtein similarity computation — now actually implemented (was a stub)** |
| D4 | Excessive Dependency Count | Low | >50 direct dependencies |
| **D5** | **Known Malicious Packages** | **Critical** | **50+ confirmed malicious npm/PyPI package names including MCP-ecosystem typosquats (@mcp/sdk, mcp-sdk, fastmcp-sdk)** |
| **D6** | **Weak Cryptography Dependencies** | **High** | **md5, sha1, RC4, DES, node-forge <1.3.0, jsonwebtoken <8.5.1, bcrypt-nodejs, crypto-js <4.2.0, pycrypto — with semver-aware version comparison** |
| **D7** | **Dependency Confusion Attack Risk** | **High** | **Scoped packages + suspiciously high version numbers (the 9999.0.0 attacker trick used in real-world attacks)** |

#### Category E — Behavioral Analysis (4 rules)

| ID | Name | Severity |
|----|------|----------|
| E1 | No Authentication Required | Medium |
| E2 | Insecure Transport (HTTP/WS) | High |
| E3 | Response Time Anomaly (>10s) | Low |
| E4 | Excessive Tool Count (>50) | Medium |

#### Category F — Ecosystem Context (7 rules)

| ID | Name | Severity | What Makes It Extraordinary |
|----|------|----------|----------------------------|
| F1 | Lethal Trifecta | Critical | Private data + untrusted content + external comms = total score cap at 40 |
| F2 | High-Risk Capability Profile | Medium | executes-code+sends-network, filesystem+sends-network, credentials+sends-network |
| F3 | Data Flow Risk Source→Sink | High | Read tools + send tools in same server |
| F4 | MCP Spec Non-Compliance | Low | **Required/recommended field checks — now actually implemented (was a stub)** |
| **F5** | **Official Namespace Squatting** | **Critical** | **Protects Anthropic, OpenAI, Google, Microsoft, AWS, GitHub, Stripe, Cloudflare namespaces. Levenshtein similarity on 12 known official server names.** |
| **F6** | **Circular Data Loop** | **High** | **Write+read on same data store enables persistent prompt injection. Attacker poisons stored content once; AI executes it on every subsequent read. Novel detection category.** |
| **F7** | **Multi-Step Exfiltration Chain** | **Critical** | **3-step chain: read sensitive data → transform/encode → exfiltrate. No individual tool is dangerous; the combination is. Cross-tool analysis not done by any other MCP tool.** |

---

### What Differentiates These Rules from All Other MCP Security Tools

1. **Unicode attack surface (A6, A7)**: Homoglyph and zero-width character attacks are not implemented by any public MCP security tooling. These are real attack vectors used in supply chain attacks.
2. **Parameter description injection (B5)**: LLMs consult parameter descriptions when filling in tool arguments. This is a second injection surface completely absent from all other MCP scanners.
3. **Circular data loop (F6)**: Persistent prompt injection via write→read cycles is a novel detection category. One poisoned database record can affect all future agent sessions.
4. **Multi-step exfiltration chain (F7)**: No single tool in the chain triggers a traditional alert. Only cross-tool analysis reveals the pattern.
5. **Secret pattern coverage (C5)**: 20+ real token formats vs. 4-5 in typical tools. Covers modern AI service tokens (Anthropic, OpenAI) that other tools haven't added yet.
6. **Levenshtein similarity (D3, F5)**: Actual string distance computation for typosquat detection, not just exact-match blocklists.
7. **Deceptive labeling (A8)**: Description vs. parameter capability mismatch is an AI-specific attack that causes agents to approve destructive operations under false pretenses.
8. **Dangerous defaults (B7)**: Checking default parameter values for least-privilege violations. Schema-focused tools check for presence of validation, not the security of default values.
9. **Dependency confusion (D7)**: High version number detection (attacker trick used in real 2021 attacks by Alex Birsan).
10. **Bugs fixed**: D3 (typosquatting) and F4 (spec compliance) were YAML stubs with no engine implementation. Both are now fully implemented.

---

### Section F: Dynamic Tool Invocation

Dynamic tool invocation (actually calling MCP server tools with test inputs) is a GATED capability:
- Not enabled in v1.0 scanning
- Requires explicit opt-in from server authors
- All test inputs are read-only canary values
- Full audit log of all invocations
- See P10 (Red Team) for the dynamic testing methodology

---

### Engine Implementation Status

| Check Type | Handler | Status |
|-----------|---------|--------|
| `regex` on `tool_description` | `getTextsForContext` | ✅ |
| `regex` on `parameter_schema` | `getTextsForContext` | ✅ |
| `regex` on `parameter_description` | `getTextsForContext` | ✅ New |
| `regex` on `source_code` | `getTextsForContext` | ✅ |
| `regex` on `metadata` | `getTextsForContext` | ✅ |
| `schema-check`: `no_input_schema` | `runSchemaCheckRule` | ✅ |
| `schema-check`: `parameter_count_exceeds` | `runSchemaCheckRule` | ✅ |
| `schema-check`: `parameter_missing_constraints` | `runSchemaCheckRule` | ✅ |
| `schema-check`: `tool_count_exceeds` | `runSchemaCheckRule` | ✅ |
| `schema-check`: `dependency_count_exceeds` | `runSchemaCheckRule` | ✅ |
| `schema-check`: `additional_properties_allowed` | `runSchemaCheckRule` | ✅ New |
| `schema-check`: `dangerous_parameter_defaults` | `runSchemaCheckRule` | ✅ New |
| `behavioral`: `connection_no_auth` | `runBehavioralRule` | ✅ |
| `behavioral`: `connection_transport` | `runBehavioralRule` | ✅ |
| `behavioral`: `response_time_exceeds` | `runBehavioralRule` | ✅ |
| `composite`: `dependency_cve_audit` | `runCompositeRule` | ✅ |
| `composite`: `dependency_last_update` | `runCompositeRule` | ✅ |
| `composite`: `dependency_name_similarity` | `runCompositeRule` | ✅ Fixed |
| `composite`: `lethal_trifecta` | `runCompositeRule` | ✅ |
| `composite`: `capability_risk_profile` | `runCompositeRule` | ✅ |
| `composite`: `data_flow_analysis` | `runCompositeRule` | ✅ |
| `composite`: `tool_name_shadows_common` | `runCompositeRule` | ✅ |
| `composite`: `spec_compliance` | `runCompositeRule` | ✅ Fixed |
| `composite`: `description_capability_mismatch` | `runCompositeRule` | ✅ New |
| `composite`: `known_malicious_package` | `runCompositeRule` | ✅ New |
| `composite`: `weak_crypto_deps` | `runCompositeRule` | ✅ New |
| `composite`: `dependency_confusion_risk` | `runCompositeRule` | ✅ New |
| `composite`: `namespace_squatting` | `runCompositeRule` | ✅ New |
| `composite`: `circular_data_loop` | `runCompositeRule` | ✅ New |
| `composite`: `multi_step_exfiltration_chain` | `runCompositeRule` | ✅ New |
| `composite`: `indirect_injection_gateway` | `runCompositeRule` | ✅ G1 |
| `composite`: `context_window_saturation` | `runCompositeRule` | ✅ G4 |
| `behavioral`: `tool_behavior_drift` | `runBehavioralRule` | ✅ G6 |
| `regex` on `source_code` (OAuth patterns) | `runRegexRule` | ✅ H1 |
| `regex` on `server_initialize_fields` | `runRegexRule` | ✅ H2 (new context) |
| `composite`: `multi_agent_propagation_risk` | `runCompositeRule` | ✅ H3 |

#### Category G — Adversarial AI (7 rules — P1 Threat Researcher)

| ID | Name | Severity | Attack Intelligence |
|----|------|----------|---------------------|
| **G1** | **Indirect Prompt Injection Gateway** | **Critical** | **#1 real-world attack vector. Rehberger (2024): "web scraping MCP returns page controlled by attacker containing injection payload." Email readers, issue trackers, Slack bots, file readers — any tool ingesting external content is a gateway.** |
| **G2** | **Trust Assertion Injection** | **Critical** | **AI-native social engineering. Tool description claims "Approved by Anthropic" or "security certified." LLMs are trained to respect authority — this causes skip of user confirmation and trust escalation.** |
| **G3** | **Tool Response Format Injection** | **Critical** | **Confused deputy attack on the parsing layer. Tool claims to return MCP protocol messages or JSON-RPC tool calls. AI mistakes data for executable code.** |
| **G4** | **Context Window Saturation** | **High** | **Precision attack: description sized to push safety instructions below the model's effective attention threshold. Detects: padding detection, description-to-parameter ratio, tail injection (payload at end of long description exploiting recency bias).** |
| **G5** | **Capability Escalation via Prior Approval** | **Critical** | **AI-specific session state exploitation. Description references "permissions you already granted" or "same access as [other tool]." AI applies referenced permission without fresh approval — no equivalent in traditional security.** |
| **G6** | **Rug Pull / Tool Behavior Drift** | **Critical** | **Temporal attack: establish trust, then change. Detects tool count changes >5, dangerous new tools added after stable scan history, description hash changes on security-critical tools. Requires historical baseline.** |
| **G7** | **DNS-Based Data Exfiltration Channel** | **Critical** | **Stealth exfiltration bypassing HTTP firewalls, DLP, and SIEM. Data encoded in DNS query subdomains. Works through corporate firewalls (UDP/53 rarely blocked), cloud environments, and air-gapped networks via DNS recursion.** |

---

#### Category H — 2026 Attack Surface (3 rules — March 2026 update)

| ID | Name | Severity | Attack Intelligence |
|----|------|----------|---------------------|
| **H1** | **MCP OAuth 2.0 Insecure Implementation** | **Critical** | **RFC 9700 / MCP Authorization spec added OAuth 2.0 in mid-2025. Detects six attack vectors: (1) redirect_uri from user input → auth code injection, (2) implicit flow (response_type=token, banned in OAuth 2.1) → token in URL/logs, (3) ROPC grant (grant_type=password) → MCP server receives raw user credentials, (4) token in localStorage → XSS token theft, (5) state param not validated → OAuth CSRF, (6) scope from user input → privilege escalation. Source code detection on OAuth implementation patterns.** |
| **H2** | **Prompt Injection in MCP Initialize Response Fields** | **Critical** | **The MCP initialize handshake fields (serverInfo.name, serverInfo.version, instructions) are processed BEFORE tool descriptions, BEFORE user context, with higher implicit trust than tool descriptions. The September 2025 MCP spec added a spec-sanctioned `instructions` field that AI clients are trained to follow. Injection here sets behavioral rules for the ENTIRE session. Zero coverage in A–G rules. Extends the analyzer context model with `server_initialize_fields` to scan these three fields. Detects: role injection, LLM special tokens, Unicode control characters, base64 payloads, authority claims, capability escalation directives.** |
| **H3** | **Multi-Agent Propagation Risk** | **High** | **Multi-agent architectures (LangGraph, AutoGen, CrewAI) are mainstream in 2026. MCP is the integration layer between agents. Detects two propagation vectors: (1) agentic input sinks — tools that accept output from other agents without declaring trust boundaries (compromised upstream agent propagates injected instructions downstream), (2) shared agent memory writers — tools writing to cross-agent state (vector stores, scratchpads, working memory) that any downstream agent reads. Documented in real-world attacks: Embrace The Red (Nov 2025), Invariant Labs (Jan 2026), Trail of Bits (Feb 2026). No equivalent in traditional security tooling.** |

