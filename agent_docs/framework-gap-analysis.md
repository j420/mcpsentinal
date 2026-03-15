# MCP Sentinel — Framework Gap Analysis & Research Findings
## Date: March 15, 2026 | Persona: P1 (Threat Intel) + P8 (Rule Engineer) + P11 (Compliance Mapper)

---

## Current State: 83 Rules Across 10 Categories (A-J)

| Category | Count | Coverage Area | Quality |
|----------|-------|--------------|---------|
| A (Description Analysis) | 9 | Prompt injection, scope, URLs, Unicode, encoding | Excellent |
| B (Schema Analysis) | 7 | Validation, parameters, defaults, additional props | Strong |
| C (Code Analysis) | 16 | Injection, traversal, SSRF, secrets, crypto, deserialization | Excellent |
| D (Dependency Analysis) | 7 | CVEs, abandoned deps, typosquatting, malicious pkgs | Strong |
| E (Behavioral Analysis) | 4 | Auth, transport, timing, tool count | Weak |
| F (Ecosystem Context) | 7 | Lethal trifecta, data flow, namespace, exfiltration chains | Excellent |
| G (Adversarial AI) | 7 | Indirect injection, trust assertion, context saturation, drift | Excellent |
| H (2026 Attack Surface) | 3 | OAuth, initialize injection, multi-agent propagation | Strong |
| I (Protocol Surface) | 16 | Annotations, resources, prompts, sampling, elicitation | Strong |
| J (Threat Intelligence) | 7 | Config poisoning, git injection, schema poisoning, output poisoning | Strong |

---

## 8 Frameworks Analyzed

| Framework | Focus | MCP Sentinel Coverage |
|-----------|-------|----------------------|
| **NIST AI RMF** (AI 100-1) | Governance, risk lifecycle | MEASURE strong, GOVERN/MAP weak |
| **OWASP Agentic Top 10** (ASI01-10) | Technical agent vulnerabilities | ASI01-07 strong, ASI08-10 partial |
| **MITRE ATLAS** (66 techniques) | Adversarial threat taxonomy | ~70% of agent techniques covered |
| **EU AI Act** (Art. 9, 15) | Regulatory compliance | Robustness strong, transparency weak |
| **ISO 42001** (Annex A) | AI management system | A.7/A.9/A.10 covered, A.8/A.9.2 gaps |
| **CoSAI MCP Security** (12 threat categories) | MCP-specific threats | MCP-T1 to T11 strong, MCP-T12 gap |
| **MAESTRO** (7 layers) | Multi-agent threat model | L1-L4, L7 strong, L5 weak |
| **CSA AICM** (243 controls) | AI controls matrix | App security strong, IAM partial |

---

## Critical Gaps (Multi-Framework Impact)

### GAP 1: Audit Trail & Observability Integrity
**Frameworks requiring it:** CoSAI MCP-T12, MAESTRO L5, NIST MEASURE, ISO 42001 A.8, OWASP ASI08
**Current coverage:** Only 3 rules (C6 error leakage, E3 response time, G6 drift)
**What's missing:**
- Detection of disabled/absent structured logging
- Detection of log deletion or truncation
- Detection of insufficient audit context (missing correlation IDs, agent identity)

**Proposed rules:**
| Rule ID | Name | Type | Context | Severity |
|---------|------|------|---------|----------|
| K1 | Absent Structured Logging | regex | source_code | high |
| K2 | Audit Trail Destruction | regex | source_code | critical |
| K3 | Insufficient Audit Context | regex | source_code | medium |

---

### GAP 2: Human Override & Kill-Switch Mechanisms
**Frameworks requiring it:** NIST GOVERN 1.7, ISO 42001 A.9.2, EU AI Act Art. 15, CoSAI MCP-T9, OWASP ASI09
**Current coverage:** I16 (consent fatigue) is tangential; no direct check
**What's missing:**
- No detection of missing confirmation/approval patterns for destructive operations
- No detection of absent cancel/abort mechanism
- No detection of auto-approve or bypass-confirmation patterns

**Proposed rules:**
| Rule ID | Name | Type | Context | Severity |
|---------|------|------|---------|----------|
| K4 | Missing Human Confirmation for Destructive Ops | composite | source_code + tool_annotations | high |
| K5 | Auto-Approve / Bypass Confirmation Pattern | regex | source_code | critical |

---

### GAP 3: Credential Scope & Lifecycle Security
**Frameworks requiring it:** OWASP ASI03, CoSAI MCP-T1, CSA AICM IAM domain, MITRE ATLAS
**Current coverage:** H1 (OAuth implementation flaws), E1 (no auth), C14 (JWT)
**What's missing:**
- No detection of overly broad OAuth scopes (scope="*" or scope containing admin/write when read suffices)
- No detection of long-lived tokens without rotation
- No detection of credentials shared across MCP server boundaries

**Proposed rules:**
| Rule ID | Name | Type | Context | Severity |
|---------|------|------|---------|----------|
| K6 | Overly Broad OAuth Scopes | regex | source_code | high |
| K7 | Long-Lived Tokens Without Rotation | regex | source_code | high |
| K8 | Cross-Boundary Credential Sharing | regex | source_code | critical |

---

### GAP 4: Advanced Supply Chain Integrity
**Frameworks requiring it:** OWASP ASI04, MITRE ATLAS, CoSAI MCP-T6/T11, MAESTRO L3
**Current coverage:** D1-D7 (CVEs, typosquatting, malicious packages, dependency confusion)
**What's missing:**
- No lockfile integrity verification (lock file ≠ manifest)
- No post-install script abuse detection (npm postinstall, setuptools hooks)
- No package registry substitution detection (.npmrc pointing to malicious registry)
- No git submodule integrity check

**Proposed rules:**
| Rule ID | Name | Type | Context | Severity |
|---------|------|------|---------|----------|
| K9 | Dangerous Post-Install Hooks | regex | source_code | critical |
| K10 | Package Registry Substitution | regex | source_code | high |
| K11 | Lockfile Integrity Mismatch | composite | metadata | high |

---

### GAP 5: Output Sanitization & Safe Return
**Frameworks requiring it:** CoSAI MCP-T4, OWASP ASI02/ASI09, MAESTRO L3
**Current coverage:** J5 (tool output poisoning patterns — detects bad outputs), G3 (response format injection)
**What's missing:**
- No detection of missing output encoding/escaping before returning to LLM
- No detection of raw user data passed through tool responses without sanitization
- No detection of tool responses containing executable patterns (JS, shell)

**Proposed rules:**
| Rule ID | Name | Type | Context | Severity |
|---------|------|------|---------|----------|
| K12 | Unsanitized Tool Output | regex | source_code | high |
| K13 | Executable Content in Tool Response | regex | source_code | critical |

---

### GAP 6: Multi-Agent Trust Boundary Enforcement
**Frameworks requiring it:** OWASP ASI07, MAESTRO L7, CoSAI MCP-T9, MITRE ATLAS
**Current coverage:** H3 (propagation risk), I13 (cross-config lethal trifecta)
**What's missing:**
- No detection of credential passing between agents via shared memory/tools
- No detection of missing agent identity verification before tool execution
- No detection of consensus bypass (single agent executing privileged ops without multi-agent agreement)

**Proposed rules:**
| Rule ID | Name | Type | Context | Severity |
|---------|------|------|---------|----------|
| K14 | Agent Credential Propagation | regex | source_code | critical |
| K15 | Missing Agent Identity Verification | composite | metadata + source_code | high |

---

### GAP 7: Cascading Failure & DoS Resistance
**Frameworks requiring it:** OWASP ASI08, EU AI Act Art. 15, CoSAI MCP-T10, MAESTRO L4
**Current coverage:** E3 (response time), E4 (tool count), G4 (context saturation)
**What's missing:**
- No detection of unbounded loops or recursive calls without depth limits
- No detection of missing timeout/circuit-breaker patterns
- No detection of memory bomb patterns (exponential allocation)

**Proposed rules:**
| Rule ID | Name | Type | Context | Severity |
|---------|------|------|---------|----------|
| K16 | Unbounded Recursion / Missing Depth Limits | regex | source_code | high |
| K17 | Missing Timeout or Circuit Breaker | regex | source_code | medium |

---

## Framework Compliance Coverage Matrix (After K-Category)

| Framework Requirement | Before (83 rules) | After (+17 K rules) |
|-----------------------|-------------------|---------------------|
| **NIST AI RMF GOVERN** | Weak | Moderate (K1-K3 audit, K4-K5 oversight) |
| **NIST AI RMF MEASURE** | Strong | Strong |
| **OWASP ASI01-ASI07** | Strong | Excellent |
| **OWASP ASI08 Cascading Failures** | Weak | Moderate (K16-K17) |
| **OWASP ASI09 Human Trust** | Weak | Moderate (K4-K5) |
| **OWASP ASI10 Rogue Agents** | Moderate | Moderate |
| **MITRE ATLAS Agent Techniques** | ~70% | ~85% |
| **EU AI Act Art. 9 Risk Management** | Moderate | Strong |
| **EU AI Act Art. 15 Robustness** | Moderate | Strong (K16-K17) |
| **ISO 42001 A.8 Transparency** | Weak | Moderate (K1-K3) |
| **ISO 42001 A.9.2 Override** | Missing | Moderate (K4-K5) |
| **CoSAI MCP-T1 Authentication** | Moderate | Strong (K6-K8) |
| **CoSAI MCP-T12 Logging** | Missing | Strong (K1-K3) |
| **MAESTRO L5 Observability** | Weak | Strong (K1-K3) |
| **CSA AICM IAM Domain** | Partial | Strong (K6-K8) |

---

## Implementation Priority

### Tier 1 — Build Now (closes multi-framework gaps)
1. **K1** Absent Structured Logging — CoSAI + MAESTRO + NIST + ISO
2. **K2** Audit Trail Destruction — CoSAI + NIST + EU AI Act
3. **K5** Auto-Approve / Bypass Confirmation — OWASP ASI09 + ISO 42001
4. **K9** Dangerous Post-Install Hooks — OWASP ASI04 + MITRE ATLAS
5. **K13** Executable Content in Tool Response — CoSAI MCP-T4 + OWASP ASI02
6. **K14** Agent Credential Propagation — OWASP ASI03/ASI07 + MAESTRO L7

### Tier 2 — Build Next Sprint
7. **K4** Missing Human Confirmation for Destructive Ops
8. **K6** Overly Broad OAuth Scopes
9. **K8** Cross-Boundary Credential Sharing
10. **K10** Package Registry Substitution
11. **K12** Unsanitized Tool Output
12. **K16** Unbounded Recursion / Missing Depth Limits

### Tier 3 — Complete Coverage
13. **K3** Insufficient Audit Context
14. **K7** Long-Lived Tokens Without Rotation
15. **K11** Lockfile Integrity Mismatch
16. **K15** Missing Agent Identity Verification
17. **K17** Missing Timeout or Circuit Breaker

---

## What This Makes Us

After K-category implementation, MCP Sentinel will have:
- **100 detection rules** across 11 categories (A-K)
- Coverage of **8 security frameworks** with documented mappings
- **7 threat categories** from the user's specification fully addressed
- Compliance evidence for **NIST AI RMF**, **OWASP Agentic Top 10**, **MITRE ATLAS**, **EU AI Act**, **ISO 42001**, **CoSAI**, **MAESTRO**, and **CSA AICM**

No other MCP security tool provides framework-mapped compliance scanning.
