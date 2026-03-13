# MCP Sentinel — Detection Rules Specification
## P8 Detection Rule Engineer Output — v2.0

### Rule Categories

| Category | Code | Requires Source Code | Rule Count |
|----------|------|---------------------|------------|
| Description Analysis | A | No | 9 |
| Schema Analysis | B | No | 7 |
| Code Analysis | C | Yes | 16 |
| Dependency Analysis | D | Yes (package manifest) | 7 |
| Behavioral Analysis | E | No (connection metadata) | 4 |
| Ecosystem Context | F | No (tool metadata) | 7 |
| **Total** | | | **50** |

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
