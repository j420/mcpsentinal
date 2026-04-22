# MCP Sentinel — Detection Rules Specification
## P8 Detection Rule Engineer Output — v4.0 (with P1 Threat Intelligence + 2026 Attack Surface)

> **Note:** All 164 active rules are `TypedRuleV2` implementations with mandatory `EvidenceChain`. The Engine Implementation Status tables below are **historical** — they document which detection approach each rule uses, but the legacy YAML dispatchers (`runRegexRule`, `runSchemaCheckRule`, `runBehavioralRule`, `runCompositeRule`) were deleted from `packages/analyzer/src/engine.ts` in Phase 1 chunk 1.28 (2026-04-22) along with the v1 `TypedRule` interface and `V1RuleAdapter`. Every row in those tables is now served by a `TypedRuleV2` registered via `registerTypedRuleV2`. Every active rule's YAML declares `detect.type: typed`. Zero YAML regex patterns and zero regex literals remain in rule authoring; the `no-static-patterns` and `charter-traceability` CI guards are always-fail. The 13 retired rules have `enabled: false` in their YAML files and no registration in the engine.

### Risk Domain Categories (Framework-Driven)

164 active rules (13 retired) are organized into **13 risk domains** derived from cross-referencing 6 compliance frameworks. Each domain maps to specific controls in OWASP MCP Top 10, OWASP Agentic Top 10, CoSAI MCP Security, MAESTRO, EU AI Act, and MITRE ATLAS. See `rules/framework-registry.yaml` for the complete many-to-many mapping.

| # | Risk Domain | Count | Frameworks | Migration Priority |
|---|---|---|---|---|
| 1 | **Prompt Injection** | 21 | MCP01, ASI01, CoSAI-T4, MAESTRO-L3, Art.15, AML.T0054 | 8 |
| 2 | **Tool Poisoning** | 15 | MCP02, ASI02, CoSAI-T4/T6/T9, MAESTRO-L3/L7, Art.13 | 10 |
| 3 | **Code Vulnerabilities** | 19 | MCP03/05/07, ASI02/05, CoSAI-T3, MAESTRO-L3, Art.15 | 9 |
| 4 | **Data Exfiltration** | 20 | MCP04, ASI06/07, CoSAI-T5, MAESTRO-L2/L7, Art.15, AML.T0057 | 6 |
| 5 | **Authentication & Identity** | 9 | MCP07, ASI03, CoSAI-T1, MAESTRO-L6, Art.15, AML.T0055 | 5 |
| 6 | **Supply Chain Security** | 26 | MCP08/10, ASI04, CoSAI-T6/T8/T11, MAESTRO-L4, Art.9 | 4 |
| 7 | **Human Oversight** | 7 | MCP06, ASI09, CoSAI-T2/T9, MAESTRO-L6, **Art.14** | **1** |
| 8 | **Audit & Logging** | 5 | MCP09, ASI10, CoSAI-T12, MAESTRO-L5, **Art.12** | **2** |
| 9 | **Multi-Agent Security** | 8 | MCP01/04/05, ASI07, CoSAI-T9, MAESTRO-L7, Art.14 | 7 |
| 10 | **Protocol & Transport** | 18 | MCP07, CoSAI-T7, MAESTRO-L4, Art.15, AML.T0061 | 5 |
| 11 | **Denial of Service** | 7 | MCP07, ASI08, CoSAI-T10, MAESTRO-L4, Art.15 | 10 |
| 12 | **Container & Runtime** | 10 | MCP07, CoSAI-T8, MAESTRO-L4, Art.15 | 3 |
| 13 | **Model Manipulation** | 12 | MCP01/06/07, ASI01/08, CoSAI-T4/T10, MAESTRO-L1, Art.15, AML.T0054/T0056 | 10 |

Migration priority 1 = migrate first (EU AI Act August 2026 deadline), 10 = migrate last.

### Legacy Rule Categories (A–Q)

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
| **Protocol Surface** | **I** | **No (protocol metadata + annotations)** | **16** | **P1 Threat Researcher (March 2026)** |
| **2026 Threat Intelligence** | **J** | **Yes (source code + tool metadata)** | **7** | **P1 Threat Researcher (CVE-backed, March 2026)** |
| **Compliance & Governance** | **K** | **Yes (source code + config)** | **20** | **P11 Compliance Mapper (8-framework mapped, March 2026)** |
| **Supply Chain Advanced** | **L** | **Yes (source code + CI config)** | **15** | **P1 Threat Researcher (CVE-backed, March 2026)** |
| **AI Runtime Exploitation** | **M** | **Mixed (tool metadata + source)** | **8 (1 retired)** | **P1 Threat Researcher (LLM attack research, March 2026)** |
| **Protocol Edge Cases** | **N** | **Yes (source code)** | **15** | **P1 Threat Researcher (JSON-RPC + transport, March 2026)** |
| **Data Privacy Attacks** | **O** | **Yes (source code)** | **6 (4 retired)** | **P1 Threat Researcher (exfiltration research, March 2026)** |
| **Infrastructure Runtime** | **P** | **Yes (source code + Dockerfiles)** | **10** | **P7 Infrastructure Engineer (container security, March 2026)** |
| **Cross-Ecosystem Emergent** | **Q** | **Mixed (source + metadata)** | **7 (8 retired)** | **P1 Threat Researcher (multi-protocol, March 2026)** |
| **Total** | | | **164 active (13 retired)** | |

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
| MCP01 | Prompt Injection | A1, A5, A7, A8, A9, B5, F1, F6, I3, I6, I7, J3, J5, J6 |
| MCP02 | Tool Poisoning | A2, A4, A6, F2, F5, I1, I2, J5, J6 |
| MCP03 | Command Injection | C1, C9, C13, C16, J2, J7 |
| MCP04 | Data Exfiltration | A3, F1, F3, F7, I9, I13 |
| MCP05 | Privilege Escalation | C2, C8, C10, C12, I4, I12, J1 |
| MCP06 | Excessive Permissions | A2, B3, B7, E4, F2, I11, I16 |
| MCP07 | Insecure Configuration | B6, C7, C8, C11, C14, C15, D6, E1, E2, I15, J4 |
| MCP08 | Dependency Vulnerabilities | D1, D2, D3, D4, D5, D6, D7 |
| MCP09 | Logging & Monitoring | C6, E3 |
| MCP10 | Supply Chain | D3, D5, D7, A4, F5, I5, I14, J7 |

### OWASP Agentic Applications Top 10 Coverage (December 2025)

MCP Sentinel is the first tool to map to both the MCP Top 10 AND the Agentic Applications Top 10.

| OWASP Agentic ID | Name | MCP Sentinel Rules |
|-------------------|------|--------------------|
| ASI01 | Agent Goal Hijack | A1, A7, A9, G2, G5, H2, I3, I6, J5, J6 |
| ASI02 | Tool Misuse | B2, B7, C1, C9, C16, I1, I2, I12, J2 |
| ASI03 | Identity & Privilege Abuse | C8, E1, H1, I11, I12, J1 |
| ASI04 | Agentic Supply Chain | D1, D3, D5, D7, F5, I5, J7 |
| ASI05 | Unexpected Code Execution | C1, C12, C13, C16, J2, J7 |
| ASI06 | Memory & Context Poisoning | F6, G1, G4, H2, H3, I3, J3, J5 |
| ASI07 | Insecure Inter-Agent Communication | F1, F7, H3, I13, J1 |

### MITRE ATLAS Agent Technique Coverage (October 2025)

| MITRE Technique | Name | MCP Sentinel Rules |
|-----------------|------|--------------------|
| AML.T0054 | LLM Prompt Injection | A1, A5, A7, A9, B5, G2, G3, G5, H2, I3, I6, J3, J5 |
| AML.T0054.001 | Indirect Prompt Injection | G1, F6, I3, J5 |
| AML.T0054.002 | Direct Prompt Injection | A1, A9, H2 |
| AML.T0057 | LLM Data Leakage | A3, F3, F7, G7, I9, J4 |
| AML.T0058 | AI Agent Context Poisoning | G4, H2, I3, I6, J3, J5 |
| AML.T0059 | Memory Manipulation | F6, H3, J1 |
| AML.T0060 | Modify AI Agent Configuration | J1 |
| AML.T0061 | Thread Injection | G3, G5, H2 |

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

### Companion Rule Pattern

There are two distinct patterns for how a single detector file covers multiple rule IDs:

#### 1. Stub-Registered Companion Rules (5 rules)

Some parent rules emit findings for multiple rule IDs during a single `analyze()` pass. The "child" rules are registered as **stub TypedRules** (returning `[]`) to prevent engine dispatch warnings — the parent rule already produces their findings. All 164 active rules are registered (13 retired rules disabled).

| Parent Rule | Stub Companion Rules | Why Companion (Not Separate) | Detector File |
|-------------|---------------------|------------------------------|---------------|
| F1 (Lethal Trifecta) | F2, F3, F6 | F2 (capability profile), F3 (data flow), and F6 (circular loop) are detected as byproducts of F1's capability graph analysis — the same graph traversal that identifies the lethal trifecta also identifies these sub-patterns | `f1-lethal-trifecta.ts` |
| I1 (Annotation Deception) | I2 | I2 (missing destructive annotation) is the inverse check of I1 (deceptive annotation) — both are evaluated during the same annotation inspection pass | `cross-tool-risk-detector.ts` |
| L5 (Manifest Confusion) | L14 | L14 (bin field shadowing / exports divergence) is detected during L5's entry point analysis of package.json manifests | `supply-chain-detector.ts` |

#### 2. Multi-Rule Emission (Full TypedRule Registrations)

Most detector files register **multiple full TypedRule implementations** — each with its own `id`, `analyze()` method, and independent engine dispatch. These are NOT stubs; the engine dispatches each rule independently. This is a code-organization pattern (grouping related rules in one file), not a parent-child dependency.

| Detector File | Rule IDs Registered | Pattern |
|---------------|-------------------|---------|
| `description-schema-detector.ts` | A1, A2, A3, A4, A5, A8, B1, B2, B3, B4, B5, B6, B7 | Factory (`makeRule()`) produces 13 independent TypedRules |
| `tainted-execution-detector.ts` | C4, C12, C13, C16, K9, J2 | Parameterized `TaintBasedRule` class instantiated per rule config |
| `code-security-deep-detector.ts` | C2, C5, C10, C14 | 4 separate TypedRule classes |
| `code-remaining-detector.ts` | C3, C6, C7, C8, C9, C11, C15 | 7 inline TypedRule objects |
| `dependency-behavioral-detector.ts` | D1, D2, D4, D5, D6, D7, E1, E2, E3, E4 | 10 inline TypedRule objects |
| `ecosystem-adversarial-detector.ts` | F4, F5, G6, H1, H3 | 5 inline TypedRule objects |
| `ai-manipulation-detector.ts` | G1, G2, G3, G5, H2 | 5 separate TypedRule classes |
| `cross-tool-risk-detector.ts` | I1, I13, I16 (+ I2 stub) | 3 full TypedRule classes + 1 stub |
| `protocol-surface-remaining-detector.ts` | I3–I15 (excl. I2), J3–J7 | 17 inline TypedRule objects |
| `config-poisoning-detector.ts` | J1, L4, L11, Q4 | 4 separate TypedRule classes |
| `secret-exfil-detector.ts` | L9, K2, G7 | 3 separate TypedRule classes |
| `supply-chain-detector.ts` | L5, L12, K10 (+ L14 stub) | 3 full TypedRule classes + 1 stub |
| `advanced-supply-chain-detector.ts` | L1, L2, L6, L7, L13, K3, K5, K8 | 8 separate TypedRule classes |
| `protocol-ai-runtime-detector.ts` | M1, M6, M9, N4–N15 (M3 retired) | 12 active TypedRule classes |
| `infrastructure-detector.ts` | P1–P7 | 7 separate TypedRule classes |
| `data-privacy-cross-ecosystem-detector.ts` | O4–O6, O8–O9, Q3–Q4, Q6–Q7, Q10, Q13 (O1–O3, O7, Q1, Q2, Q5, Q8, Q9, Q11, Q12 retired) | Factory-built TypedRules |
| `compliance-remaining-detector.ts` | K1, K4, K6, K7, K11–K20, L3, L8, L10, L15, M2, M4, M5, M7, M8, N1–N3, O4–O6, O8–O10, P8–P10, Q3, Q4, Q6, Q7, Q10, Q13, Q15 (Q2, Q5, Q8, Q9, Q11, Q12, Q14 retired) | Factory (`buildRule()`) produces rules from config array |

Single-rule detector files: `c1-command-injection.ts` (C1), `a9-encoded-instructions.ts` (A9), `d3-typosquatting.ts` (D3), `g4-context-saturation.ts` (G4). Also `a6-unicode-homoglyph.ts` (A6 + A7 as 2 independent classes) and `f1-lethal-trifecta.ts` (F1 + F7 as 2 independent classes, plus 3 stubs).

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

---

#### Category I — Protocol Surface Attacks (16 rules — P1 Threat Researcher, March 2026)

Rules A–H cover the classic attack surfaces. Category I targets the **MCP protocol surface itself** — capabilities, annotations, resources, prompts, roots, sampling, and elicitation that were added or gained widespread adoption in the 2025-03-26 and 2025-06-18 spec revisions. These protocol primitives create attack surfaces that didn't exist when rules A–H were authored.

**Primary threat intelligence sources for I-rules:**
- MCP Specification `2025-03-26`: Tool annotations (readOnlyHint, destructiveHint, idempotentHint, openWorldHint)
- MCP Specification `2025-06-18`: Elicitation capability (server requests structured user data)
- arXiv 2601.17549: Sampling capability abuse — 23-41% attack amplification
- Invariant Labs (2025): Consent fatigue exploitation — 84.2% tool poisoning success with auto-approve
- CVE-2025-53109/53110: Anthropic filesystem server root boundary bypass
- CVE-2025-6514: mcp-remote OS command injection (CVSS 9.6)
- CVE-2025-6515: Session hijacking via URI manipulation in Streamable HTTP

| ID | Name | Severity | Attack Intelligence |
|----|------|----------|---------------------|
| **I1** | **Annotation Deception** | **Critical** | **Tool declares `readOnlyHint: true` but has destructive parameters (delete, remove, drop, overwrite). AI clients trust annotations for auto-approval — deceptive annotations bypass user consent entirely.** |
| **I2** | **Missing Destructive Annotation** | **High** | **Tool with destructive capability patterns but no `destructiveHint: true` annotation. Absence of annotation causes AI clients to treat the tool as safe for auto-execution.** |
| **I3** | **Resource Metadata Injection** | **Critical** | **Prompt injection patterns in resource name, description, or URI fields. Resources are processed alongside tools and can contain injection payloads in their metadata.** |
| **I4** | **Dangerous Resource URI** | **Critical** | **Resources with dangerous URI schemes (file://, data:, javascript:) or path traversal patterns (../, %2e%2e). Enables filesystem access, data injection, or XSS via resource URIs.** |
| **I5** | **Resource-Tool Shadowing** | **High** | **Resources whose names shadow common tool names (read_file, execute, write, etc.). Creates confusion between resource access and tool invocation in AI clients.** |
| **I6** | **Prompt Template Injection** | **Critical** | **Prompt injection or template interpolation patterns in prompt metadata. Prompt templates that accept user input without sanitization enable injection via the prompts/get endpoint.** |
| **I7** | **Sampling Capability Abuse** | **Critical** | **Server declares sampling capability AND has content ingestion tools. Sampling lets the server call back into the AI client — combined with content ingestion, this creates a super-injection feedback loop with 23-41% attack amplification (arXiv 2601.17549).** |
| **I8** | **Sampling Cost Attack** | **High** | **Server declares sampling capability without cost controls. Each sampling request triggers an AI inference, enabling unbounded cost amplification attacks.** |
| **I9** | **Elicitation Credential Harvesting** | **Critical** | **Tool descriptions suggest collecting credentials, passwords, tokens, or PII via elicitation. The elicitation capability (spec 2025-06-18) lets servers request structured data from users — social engineering at protocol level.** |
| **I10** | **Elicitation URL Redirect** | **High** | **Tool descriptions suggest redirecting users to external URLs for authentication or data entry. Uses elicitation to send users to attacker-controlled sites.** |
| **I11** | **Over-Privileged Root** | **High** | **Roots declared at sensitive system directories (/, /etc, /root, ~/.ssh, etc.). Roots define the server's filesystem scope — overly broad roots expose sensitive data.** |
| **I12** | **Capability Escalation Post-Init** | **Critical** | **Server uses capabilities it didn't declare during initialization. Tools reference resources/prompts/sampling but the server didn't declare those capabilities — indicates undeclared privilege escalation.** |
| **I13** | **Cross-Config Lethal Trifecta** | **Critical** | **The lethal trifecta (private data + untrusted content + external comms) distributed across multiple servers in the same client config. Single-server F1 misses this because no individual server has all three. Score CAPPED at 40 when detected.** |
| **I14** | **Rolling Capability Drift** | **High** | **Gradual tool addition over multiple scan windows (boiling frog). Unlike G6 which detects sudden changes, I14 detects slow escalation that stays below per-scan thresholds but accumulates dangerous capabilities over time.** |
| **I15** | **Transport Session Security** | **High** | **Weak session management in Streamable HTTP transport: predictable session tokens, missing session expiration, no CSRF protection, TLS configuration issues. Targets CVE-2025-6515-class vulnerabilities.** |
| **I16** | **Consent Fatigue Exploitation** | **High** | **Many benign tools (>10) hiding a few dangerous ones (<3). Exploits user approval fatigue — after approving 10 safe tools, users auto-approve the 11th without scrutiny. 84.2% success rate (Invariant Labs).** |

### Engine Implementation Status (Category I additions)

| Check Type | Handler | Status |
|-----------|---------|--------|
| `composite`: `annotation_deception` | `runCompositeRule` | ✅ I1 |
| `composite`: `missing_destructive_annotation` | `runCompositeRule` | ✅ I2 |
| `regex` on `resource_metadata` | `runRegexRule` | ✅ I3 (new context) |
| `composite`: `dangerous_resource_uri` | `runCompositeRule` | ✅ I4 |
| `composite`: `resource_tool_shadowing` | `runCompositeRule` | ✅ I5 |
| `regex` on `prompt_metadata` | `runRegexRule` | ✅ I6 (new context) |
| `composite`: `sampling_abuse` | `runCompositeRule` | ✅ I7 |
| `composite`: `sampling_cost_risk` | `runCompositeRule` | ✅ I8 |
| `regex` on `tool_description` | `runRegexRule` | ✅ I9 |
| `regex` on `tool_description` | `runRegexRule` | ✅ I10 |
| `composite`: `over_privileged_root` | `runCompositeRule` | ✅ I11 |
| `composite`: `capability_escalation_post_init` | `runCompositeRule` | ✅ I12 |
| `composite`: `cross_config_lethal_trifecta` | `runCompositeRule` | ✅ I13 |
| `behavioral`: `rolling_capability_drift` | `runBehavioralRule` | ✅ I14 |
| `regex` on `source_code` | `runRegexRule` | ✅ I15 |
| `composite`: `consent_fatigue_profile` | `runCompositeRule` | ✅ I16 |

### New Analyzer Contexts (Category I)

| Context | What It Provides | Used By |
|---------|-----------------|---------|
| `resource_metadata` | Resource name, description, URI concatenated for regex scanning | I3 |
| `prompt_metadata` | Prompt name, description, argument descriptions concatenated | I6 |
| `tool_annotations` | Serialized annotation objects for pattern matching | I1, I2 |

### New AnalysisContext Fields (Category I)

```typescript
// Added to AnalysisContext interface
resources?: Array<{ uri: string; name: string; description: string | null; mimeType: string | null }>;
prompts?: Array<{ name: string; description: string | null; arguments: Array<{ name: string; description: string | null; required: boolean }> }>;
roots?: Array<{ uri: string; name: string | null }>;
declared_capabilities?: { tools?: boolean; resources?: boolean; prompts?: boolean; sampling?: boolean; logging?: boolean } | null;
```

---

#### Category J — 2026 Threat Intelligence (7 rules — CVE-backed, P1 Threat Researcher)

These rules are derived from **real-world CVEs and published attack research** from 2025-2026. Every rule is backed by at least one confirmed vulnerability or documented attack technique.

| ID | Name | Severity | Intelligence Source |
|----|------|----------|---------------------|
| **J1** | **Cross-Agent Configuration Poisoning** | **Critical** | **Embrace The Red (2025), CVE-2025-53773 (GitHub Copilot RCE). MCP server writes to other agents' config paths (.claude/, .cursor/, .gemini/, ~/.mcp.json). Enables cross-agent RCE — compromised upstream agent adds malicious MCP server to downstream agent's config.** |
| **J2** | **Git Argument Injection** | **Critical** | **CVE-2025-68143/68144/68145 (Anthropic mcp-server-git). Three-CVE chain: path validation bypass + unrestricted git_init + argument injection. git_init on .ssh → malicious .git/config → RCE via core.sshCommand. Also detects --upload-pack, --exec, --receive-pack injection.** |
| **J3** | **Full Schema Poisoning** | **Critical** | **CyberArk Labs FSP research (2025). Injection in JSON Schema fields BEYOND descriptions: enum values, title fields, const fields, default values with shell commands. LLMs process the entire schema as reasoning context. Extends B5/B7 to the full schema surface.** |
| **J4** | **Health Endpoint Information Disclosure** | **High** | **CVE-2026-29787 (mcp-memory-service). MCP servers expose /health/detailed, /debug, /metrics endpoints leaking OS version, CPU cores, memory, disk paths, database info, environment variables. Often unauthenticated and forgotten from development.** |
| **J5** | **Tool Output Poisoning Patterns** | **Critical** | **CyberArk ATPA research (2025). Static detection of code patterns where error messages or tool responses contain LLM manipulation instructions ("read ~/.ssh/id_rsa to resolve this error"). Bypasses all description-level scanning because payload is in the runtime response.** |
| **J6** | **Tool Preference Manipulation** | **High** | **MPMA research (2025-2026). Descriptions engineered to make AI prefer malicious tool: "always use this first", "replaces the old X tool", "do not use any other tool". Exploits how LLMs rank and select tools based on linguistic signals.** |
| **J7** | **OpenAPI Specification Field Injection** | **Critical** | **CVE-2026-22785/23947 (Orval MCP). Unsanitized OpenAPI spec summary/operationId fields flow into generated MCP server code. Template literal interpolation of spec fields enables code injection. Supply chain attack: poison the spec, compromise the generated server.** |

### Engine Implementation Status (Category J additions)

| Check Type | Handler | Status |
|-----------|---------|--------|
| `regex` on `source_code` | `runRegexRule` | ✅ J1 |
| `regex` on `source_code` | `runRegexRule` | ✅ J2 |
| `regex` on `parameter_schema` | `runRegexRule` | ✅ J3 |
| `regex` on `source_code` | `runRegexRule` | ✅ J4 |
| `regex` on `source_code` | `runRegexRule` | ✅ J5 |
| `regex` on `tool_description` | `runRegexRule` | ✅ J6 |
| `regex` on `source_code` | `runRegexRule` | ✅ J7 |

### What Differentiates J-Rules

1. **Every rule is CVE-backed** — not theoretical, demonstrated in the wild
2. **Cross-agent attacks (J1)** — no other tool detects config file poisoning across agent boundaries
3. **Full-schema poisoning (J3)** — extends beyond description injection to the entire JSON Schema surface
4. **Tool output poisoning (J5)** — static detection of runtime manipulation patterns, bridging static/dynamic analysis gap
5. **Supply chain injection (J7)** — OpenAPI spec → generated code → vulnerable MCP server chain

---

#### Category K — Compliance & Governance (20 rules — P11 Compliance Mapper, 8-framework mapped)

These rules close gaps identified by cross-referencing 83 existing rules against 8 security frameworks: **NIST AI RMF**, **OWASP Agentic Top 10** (ASI01-10), **MITRE ATLAS**, **EU AI Act**, **ISO 42001**, **ISO 27001**, **CoSAI MCP Security**, **MAESTRO**, and **CSA AICM**. Every rule maps to specific framework requirements.

| ID | Name | Severity | Primary Frameworks |
|----|------|----------|-------------------|
| **K1** | **Absent Structured Logging** | **High** | **CoSAI MCP-T12, MAESTRO L5, NIST MEASURE, ISO 27001 A.8.15** |
| **K2** | **Audit Trail Destruction** | **Critical** | **ISO 27001 A.8.15, EU AI Act Art. 12, CoSAI MCP-T12** |
| **K3** | **Audit Log Tampering** | **Critical** | **ISO 27001 A.8.15, NIST MEASURE, MAESTRO L5** |
| **K4** | **Missing Human Confirmation for Destructive Ops** | **High** | **ISO 42001 A.9.1/A.9.2, EU AI Act Art. 14, NIST GOVERN 1.7** |
| **K5** | **Auto-Approve / Bypass Confirmation Pattern** | **Critical** | **OWASP ASI09, EU AI Act Art. 14, ISO 42001 A.9.2** |
| **K6** | **Overly Broad OAuth Scopes** | **High** | **OWASP ASI03, CoSAI MCP-T1/T2, ISO 27001 A.5.15/A.5.18** |
| **K7** | **Long-Lived Tokens Without Rotation** | **High** | **OWASP ASI03, CoSAI MCP-T1, ISO 27001 A.8.24** |
| **K8** | **Cross-Boundary Credential Sharing** | **Critical** | **OWASP ASI03/ASI07, CoSAI MCP-T1, ISO 27001 A.5.17, MAESTRO L7** |
| **K9** | **Dangerous Post-Install Hooks** | **Critical** | **OWASP ASI04, MITRE ATLAS AML.T0017, CoSAI MCP-T6/T11** |
| **K10** | **Package Registry Substitution** | **High** | **OWASP ASI04, ISO 27001 A.5.21, CoSAI MCP-T6** |
| **K11** | **Missing Server Integrity Verification** | **High** | **CoSAI MCP-T6/T11, ISO 27001 A.8.24/A.5.20, MAESTRO L3** |
| **K12** | **Executable Content in Tool Response** | **Critical** | **CoSAI MCP-T4, OWASP ASI02/ASI09** |
| **K13** | **Unsanitized Tool Output** | **High** | **CoSAI MCP-T4, OWASP ASI02, MAESTRO L3** |
| **K14** | **Agent Credential Propagation via Shared State** | **Critical** | **OWASP ASI03/ASI07, MAESTRO L7, MITRE ATLAS AML.T0086** |
| **K15** | **Multi-Agent Collusion Preconditions** | **High** | **MAESTRO L7, CoSAI MCP-T9, OWASP ASI07** |
| **K16** | **Unbounded Recursion / Missing Depth Limits** | **High** | **OWASP ASI08, EU AI Act Art. 15, CoSAI MCP-T10** |
| **K17** | **Missing Timeout or Circuit Breaker** | **Medium** | **OWASP ASI08, EU AI Act Art. 15, MAESTRO L4** |
| **K18** | **Cross-Trust-Boundary Data Flow in Tool Response** | **High** | **CoSAI MCP-T5, NIST Cyber AI Profile, ISO 27001 A.5.14** |
| **K19** | **Missing Runtime Sandbox Enforcement** | **High** | **CoSAI MCP-T8, ISO 27001 A.8.22, MAESTRO L4** |
| **K20** | **Insufficient Audit Context in Logging** | **Medium** | **ISO 27001 A.8.15, ISO 42001 A.8.1, MAESTRO L5** |

### Engine Implementation Status (Category K)

| Check Type | Handler | Status |
|-----------|---------|--------|
| `regex` on `source_code` | `runRegexRule` | ✅ K1 |
| `regex` on `source_code` | `runRegexRule` | ✅ K2 |
| `regex` on `source_code` | `runRegexRule` | ✅ K3 |
| `regex` on `source_code` | `runRegexRule` | ✅ K4 |
| `regex` on `source_code` | `runRegexRule` | ✅ K5 |
| `regex` on `source_code` | `runRegexRule` | ✅ K6 |
| `regex` on `source_code` | `runRegexRule` | ✅ K7 |
| `regex` on `source_code` | `runRegexRule` | ✅ K8 |
| `regex` on `source_code` | `runRegexRule` | ✅ K9 |
| `regex` on `source_code` | `runRegexRule` | ✅ K10 |
| `regex` on `source_code` | `runRegexRule` | ✅ K11 |
| `regex` on `source_code` | `runRegexRule` | ✅ K12 |
| `regex` on `source_code` | `runRegexRule` | ✅ K13 |
| `regex` on `source_code` | `runRegexRule` | ✅ K14 |
| `regex` on `source_code` | `runRegexRule` | ✅ K15 |
| `regex` on `source_code` | `runRegexRule` | ✅ K16 |
| `regex` on `source_code` | `runRegexRule` | ✅ K17 |
| `regex` on `source_code` | `runRegexRule` | ✅ K18 |
| `regex` on `source_code` | `runRegexRule` | ✅ K19 |
| `regex` on `source_code` | `runRegexRule` | ✅ K20 |

### 8-Framework Coverage Matrix

| Framework | Covered By K-Rules | Specific Requirements Addressed |
|-----------|-------------------|-------------------------------|
| **NIST AI RMF** | K1-K3 (MEASURE), K4-K5 (GOVERN) | GOVERN 1.7 override, MEASURE 2.6 audit evidence |
| **OWASP Agentic Top 10** | K5 (ASI09), K6-K8 (ASI03), K9 (ASI04), K12 (ASI02), K14-K15 (ASI07), K16-K17 (ASI08) | ASI02-ASI09 all addressed |
| **MITRE ATLAS** | K9 (AML.T0017), K14 (AML.T0086) | Supply chain, agent tool exfiltration |
| **EU AI Act** | K2 (Art. 12), K4-K5 (Art. 14), K16-K17 (Art. 15) | Record-keeping, human oversight, robustness |
| **ISO 42001** | K4-K5 (A.9.1/A.9.2), K1/K20 (A.8.1) | Human-in-the-loop, transparency |
| **ISO 27001** | K1-K3/K20 (A.8.15), K6 (A.5.15), K7 (A.8.24), K8 (A.5.17), K10 (A.5.21), K11 (A.5.20), K18 (A.5.14), K19 (A.8.22) | 10 Annex A controls covered |
| **CoSAI MCP Security** | K1-K3 (MCP-T12), K6-K8 (MCP-T1/T2), K9-K11 (MCP-T6/T11), K12-K13 (MCP-T4), K15 (MCP-T9), K16-K17 (MCP-T10), K18 (MCP-T5), K19 (MCP-T8) | 9 of 12 threat categories addressed |
| **MAESTRO** | K1-K3/K20 (L5), K14-K15 (L7), K16-K17/K19 (L4), K11/K13 (L3) | L3-L5, L7 addressed |
| **CSA AICM** | K6-K8 (IAM domain), K9-K11 (Supply Chain) | IAM + Supply Chain domains |

### What Differentiates K-Rules

1. **Every rule maps to specific framework requirements** — not general "best practices" but traceable to ISO control IDs, OWASP ASI numbers, CoSAI threat categories
2. **Audit trail integrity (K1-K3, K20)** — no other MCP security tool checks for logging adequacy, log destruction, or log tampering
3. **Human oversight enforcement (K4-K5)** — detects anti-patterns that undermine human-in-the-loop safety
4. **Credential lifecycle (K6-K8)** — goes beyond "is auth present?" to "is auth PROPERLY scoped and rotated?"
5. **Cross-trust-boundary data flow (K18)** — detects sensitive data flowing from high-sensitivity sources through low-sensitivity tool responses
6. **Multi-agent collusion preconditions (K15)** — detects static enablers of runtime collusion behavior
7. **Sandbox enforcement (K19)** — detects Docker/container misconfigurations that disable security boundaries

---

### Retired Rules (13 rules)

The following 13 rules have been retired from active scanning. They remain in `rules/` as YAML files with `enabled: false`, but their TypedRule registrations have been removed from the engine. Retired rules produce no findings and do not affect scores.

**Retirement criteria:** A rule is retired when it meets one or more of: (1) pure string-matching with no feasible path to real analysis, (2) false-positive rate exceeding 50%, (3) coverage fully duplicated by a deeper rule.

| Rule ID | Name | Category | FP Rate | Reason |
|---------|------|----------|---------|--------|
| **O1** | Steganographic Data Exfiltration | Data Privacy | >60% | Keyword matching only; covered by C3/L9/G7 taint analysis |
| **O2** | HTTP Header Covert Channel | Data Privacy | >70% | Custom headers are universal in HTTP; covered by C3 taint |
| **O3** | AI-Mediated Exfiltration via Tool Arguments | Data Privacy | >80% | Encoding before API calls is legitimate and universal |
| **O7** | Cross-Session Data Leakage | Data Privacy | >50% | Module-level state is normal in Node.js; needs runtime analysis (not static) |
| **Q1** | Dual-Protocol Schema Constraint Loss | Cross-Ecosystem | >60% | Cannot statically verify constraint loss across protocol boundaries |
| **Q2** | LangChain Serialization Bridge Injection | Cross-Ecosystem | >70% | Fully duplicated by C12 (Unsafe Deserialization) |
| **Q5** | MCP Gateway Trust Delegation Confusion | Cross-Ecosystem | >65% | Too abstract; trust delegation patterns are architecturally legitimate |
| **Q8** | Cross-Protocol Authentication Confusion | Cross-Ecosystem | >55% | Token reuse across protocols is common and often intentional |
| **Q9** | Agentic Workflow DAG Manipulation | Cross-Ecosystem | >80% | Dynamic workflow modification is legitimate in agentic frameworks |
| **Q11** | Code Suggestion Poisoning via MCP | Cross-Ecosystem | >70% | Code generation tools legitimately return code in responses |
| **Q12** | Browser Extension MCP Bridge | Cross-Ecosystem | >50% | Niche pattern; duplicated by Q7 (Extension Privilege Escalation) |
| **Q14** | Cross-Language Serialization Mismatch | Cross-Ecosystem | N/A | Pattern unmatchable via static analysis; rule never fires |
| **M3** | Reasoning Chain Manipulation | AI Runtime | N/A | Fully duplicated by A1 linguistic scoring (higher precision) |

