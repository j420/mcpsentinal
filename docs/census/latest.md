# Rule Census

_Generated: 2026-04-22T09:46:21.122Z_

## Summary

| Metric | Value |
|---|---|
| YAML rules (total) | 177 |
| YAML rules (enabled) | 164 |
| Registered rules (unique ids) | 66 |
| Registered v1 | 56 |
| Registered v2 | 10 |
| Enabled but unregistered | 111 |
| Detector files | 11 |
| Files with any regex | 11 |
| Files with any technique import | 3 |

## Aggregate Technique Observations

| Signal | Count |
|---|---|
| Regex literals | 262 |
| new RegExp(...) calls | 2 |
| String-literal arrays > 5 | 1 |
| Rules using taint-ast | 16 |
| Rules using capability-graph | 21 |
| Rules using module-graph | 0 |
| Rules using entropy | 0 |
| Rules using similarity | 0 |
| Rules using EvidenceChainBuilder | 66 |

## Top Regex Offenders (detector files)

| File | Regex literals | new RegExp calls |
|---|---:|---:|
| `packages/analyzer/src/rules/implementations/m-runtime-v2.ts` | 43 | 0 |
| `packages/analyzer/src/rules/implementations/data-privacy-cross-ecosystem-detector.ts` | 38 | 0 |
| `packages/analyzer/src/rules/implementations/protocol-ai-runtime-detector.ts` | 33 | 0 |
| `packages/analyzer/src/rules/implementations/protocol-surface-remaining-detector.ts` | 33 | 0 |
| `packages/analyzer/src/rules/implementations/k-compliance-v2.ts` | 27 | 0 |
| `packages/analyzer/src/rules/implementations/cross-tool-risk-detector.ts` | 23 | 0 |
| `packages/analyzer/src/rules/implementations/o4-q10-v2.ts` | 23 | 0 |
| `packages/analyzer/src/rules/implementations/l-supply-chain-v2.ts` | 15 | 2 |
| `packages/analyzer/src/rules/implementations/m5-context-window-flooding.ts` | 11 | 0 |
| `packages/analyzer/src/rules/implementations/m4-tool-squatting.ts` | 9 | 0 |

## Per-Rule Detail

Columns: enabled (E), v1 registered (1), v2 registered (2), regex count (R), analyzer toolkit (T).
T = first-letter tags: a=ast-taint, c=capability-graph, m=module-graph, e=entropy, s=similarity, i=schema-inference, v=EvidenceChainBuilder.

> _Registration harvest caveat: for detectors of the form_ `for (cfg of RULES) registerTypedRule(buildRule(cfg))`, _the census credits every config object with an `id:` property, even if the runtime loop filters some out. Regex counts and toolkit imports are exact._

| ID | Name | Cat | Sev | E | 1 | 2 | R | T | Detector |
|---|---|---|---|:-:|:-:|:-:|---:|---|---|
| A1 | Prompt Injection in Tool Description | description-analysis | critical | Y |  |  | 0 | — | — |
| A2 | Excessive Scope Claims in Description | description-analysis | high | Y |  |  | 0 | — | — |
| A3 | Suspicious URLs in Tool Description | description-analysis | medium | Y |  |  | 0 | — | — |
| A4 | Cross-Server Tool Name Shadowing | description-analysis | high | Y |  |  | 0 | — | — |
| A5 | Description Length Anomaly | description-analysis | low | Y |  |  | 0 | — | — |
| A6 | Unicode Homoglyph Attack in Tool Name or Description | description-analysis | critical | Y |  |  | 0 | — | — |
| A7 | Zero-Width and Invisible Character Injection | description-analysis | critical | Y |  |  | 0 | — | — |
| A8 | Description-Capability Mismatch (Read-Only Claim with Write Parameters) | description-analysis | high | Y |  |  | 0 | — | — |
| A9 | Encoded or Obfuscated Instructions in Tool Description | description-analysis | critical | Y |  |  | 0 | — | — |
| B1 | Missing Input Validation | schema-analysis | medium | Y |  |  | 0 | — | — |
| B2 | Dangerous Parameter Types | schema-analysis | high | Y |  |  | 0 | — | — |
| B3 | Excessive Parameter Count | schema-analysis | low | Y |  |  | 0 | — | — |
| B4 | Schema-less Tool | schema-analysis | medium | Y |  |  | 0 | — | — |
| B5 | Prompt Injection in Parameter Description | schema-analysis | critical | Y |  |  | 0 | — | — |
| B6 | Schema Allows Unconstrained Additional Properties | schema-analysis | medium | Y |  |  | 0 | — | — |
| B7 | Dangerous Default Parameter Values | schema-analysis | high | Y |  |  | 0 | — | — |
| C1 | Command Injection | code-analysis | critical | Y |  |  | 0 | — | — |
| C2 | Path Traversal | code-analysis | critical | Y |  |  | 0 | — | — |
| C3 | Server-Side Request Forgery (SSRF) | code-analysis | high | Y |  |  | 0 | — | — |
| C4 | SQL Injection | code-analysis | critical | Y |  |  | 0 | — | — |
| C5 | Hardcoded Secrets in Source Code | code-analysis | critical | Y |  |  | 0 | — | — |
| C6 | Error Message Information Leakage | code-analysis | medium | Y |  |  | 0 | — | — |
| C7 | Wildcard CORS Configuration | code-analysis | high | Y |  |  | 0 | — | — |
| C8 | No Authentication on Network-Exposed Server | code-analysis | high | Y |  |  | 0 | — | — |
| C9 | Excessive Filesystem Scope | code-analysis | high | Y |  |  | 0 | — | — |
| C10 | Prototype Pollution | code-analysis | critical | Y |  |  | 0 | — | — |
| C11 | ReDoS — Catastrophic Regex Backtracking | code-analysis | high | Y |  |  | 0 | — | — |
| C12 | Unsafe Deserialization | code-analysis | critical | Y |  |  | 0 | — | — |
| C13 | Server-Side Template Injection (SSTI) | code-analysis | critical | Y |  |  | 0 | — | — |
| C14 | JWT Algorithm Confusion / None Algorithm Attack | code-analysis | critical | Y |  |  | 0 | — | — |
| C15 | Timing Attack on Secret or Token Comparison | code-analysis | high | Y |  |  | 0 | — | — |
| C16 | Dynamic Code Evaluation with User Input | code-analysis | critical | Y |  |  | 0 | — | — |
| D1 | Known CVEs in Dependencies | dependency-analysis | high | Y |  |  | 0 | — | — |
| D2 | Abandoned Dependencies | dependency-analysis | medium | Y |  |  | 0 | — | — |
| D3 | Typosquatting Risk in Dependencies | dependency-analysis | high | Y |  |  | 0 | — | — |
| D4 | Excessive Dependency Count | dependency-analysis | low | Y |  |  | 0 | — | — |
| D5 | Known Malicious or Flagged Package | dependency-analysis | critical | Y |  |  | 0 | — | — |
| D6 | Weak or Deprecated Cryptography Dependencies | dependency-analysis | high | Y |  |  | 0 | — | — |
| D7 | Dependency Confusion Attack Risk | dependency-analysis | high | Y |  |  | 0 | — | — |
| E1 | No Authentication Required | behavioral-analysis | medium | Y |  |  | 0 | — | — |
| E2 | Insecure Transport | behavioral-analysis | high | Y |  |  | 0 | — | — |
| E3 | Response Time Anomaly | behavioral-analysis | low | Y |  |  | 0 | — | — |
| E4 | Excessive Tool Count | behavioral-analysis | medium | Y |  |  | 0 | — | — |
| F1 | Lethal Trifecta - Private Data + Untrusted Content + External Communication | ecosystem-context | critical | Y |  |  | 0 | — | — |
| F2 | High-Risk Capability Profile | ecosystem-context | medium | Y |  |  | 0 | — | — |
| F3 | Data Flow Risk - Source to Sink | ecosystem-context | high | Y |  |  | 0 | — | — |
| F4 | MCP Spec Non-Compliance | ecosystem-context | low | Y |  |  | 0 | — | — |
| F5 | Official Namespace Squatting | ecosystem-context | critical | Y |  |  | 0 | — | — |
| F6 | Circular Data Loop — Persistent Prompt Injection Storage Risk | ecosystem-context | high | Y |  |  | 0 | — | — |
| F7 | Multi-Step Exfiltration Chain | ecosystem-context | critical | Y |  |  | 0 | — | — |
| G1 | Indirect Prompt Injection Gateway | adversarial-ai | critical | Y |  |  | 0 | — | — |
| G2 | Trust Assertion Injection | adversarial-ai | critical | Y |  |  | 0 | — | — |
| G3 | Tool Response Format Injection | adversarial-ai | critical | Y |  |  | 0 | — | — |
| G4 | Context Window Saturation Attack | adversarial-ai | high | Y |  |  | 0 | — | — |
| G5 | Capability Escalation via Prior Approval Reference | adversarial-ai | critical | Y |  |  | 0 | — | — |
| G6 | Tool Behavior Drift (Rug Pull Detection) | adversarial-ai | critical | Y |  |  | 0 | — | — |
| G7 | DNS-Based Data Exfiltration Channel | adversarial-ai | critical | Y |  |  | 0 | — | — |
| H1 | MCP OAuth 2.0 Insecure Implementation | auth-analysis | critical | Y |  |  | 0 | — | — |
| H2 | Prompt Injection in MCP Initialize Response Fields | adversarial-ai | critical | Y |  |  | 0 | — | — |
| H3 | Multi-Agent Propagation Risk | adversarial-ai | high | Y |  |  | 0 | — | — |
| I1 | Tool Annotation Deception | protocol-surface | critical | Y | Y |  | 23 | civ | `cross-tool-risk-detector.ts` |
| I2 | Missing Destructive Tool Annotation | protocol-surface | high | Y | Y |  | 23 | civ | `cross-tool-risk-detector.ts` |
| I3 | Prompt Injection in Resource Metadata | protocol-surface | critical | Y | Y |  | 33 | cv | `protocol-surface-remaining-detector.ts` |
| I4 | Dangerous Resource URI Scheme | protocol-surface | critical | Y | Y |  | 33 | cv | `protocol-surface-remaining-detector.ts` |
| I5 | Resource-Tool Name Shadowing | protocol-surface | high | Y | Y |  | 33 | cv | `protocol-surface-remaining-detector.ts` |
| I6 | Prompt Template Injection | protocol-surface | critical | Y | Y |  | 33 | cv | `protocol-surface-remaining-detector.ts` |
| I7 | Sampling Capability Abuse | protocol-surface | critical | Y | Y |  | 33 | cv | `protocol-surface-remaining-detector.ts` |
| I8 | Sampling Cost / Resource Theft | protocol-surface | high | Y | Y |  | 33 | cv | `protocol-surface-remaining-detector.ts` |
| I9 | Elicitation Credential Harvesting | protocol-surface | critical | Y | Y |  | 33 | cv | `protocol-surface-remaining-detector.ts` |
| I10 | Elicitation URL Redirect Risk | protocol-surface | high | Y | Y |  | 33 | cv | `protocol-surface-remaining-detector.ts` |
| I11 | Over-Privileged Root Declaration | protocol-surface | high | Y | Y |  | 33 | cv | `protocol-surface-remaining-detector.ts` |
| I12 | Capability Escalation Post-Initialization | protocol-surface | critical | Y | Y |  | 33 | cv | `protocol-surface-remaining-detector.ts` |
| I13 | Cross-Config Lethal Trifecta | protocol-surface | critical | Y | Y |  | 23 | civ | `cross-tool-risk-detector.ts` |
| I14 | Rolling Capability Drift | protocol-surface | high | Y | Y |  | 33 | cv | `protocol-surface-remaining-detector.ts` |
| I15 | Transport Session Security | protocol-surface | high | Y | Y |  | 33 | cv | `protocol-surface-remaining-detector.ts` |
| I16 | Consent Fatigue Exploitation | protocol-surface | high | Y | Y |  | 23 | civ | `cross-tool-risk-detector.ts` |
| J1 | Cross-Agent Configuration Poisoning | threat-intelligence | critical | Y |  |  | 0 | — | — |
| J2 | Git Argument Injection | threat-intelligence | critical | Y |  |  | 0 | — | — |
| J3 | Full Schema Poisoning | threat-intelligence | critical | Y | Y |  | 33 | cv | `protocol-surface-remaining-detector.ts` |
| J4 | Health Endpoint Information Disclosure | threat-intelligence | high | Y | Y |  | 33 | cv | `protocol-surface-remaining-detector.ts` |
| J5 | Tool Output Poisoning Patterns | threat-intelligence | critical | Y | Y |  | 33 | cv | `protocol-surface-remaining-detector.ts` |
| J6 | Tool Preference Manipulation | threat-intelligence | high | Y | Y |  | 33 | cv | `protocol-surface-remaining-detector.ts` |
| J7 | OpenAPI Specification Field Injection | threat-intelligence | critical | Y | Y |  | 33 | cv | `protocol-surface-remaining-detector.ts` |
| K1 | Absent Structured Logging | compliance-governance | high | Y |  |  | 0 | — | — |
| K2 | Audit Trail Destruction | compliance-governance | critical | Y |  |  | 0 | — | — |
| K3 | Audit Log Tampering | compliance-governance | critical | Y |  |  | 0 | — | — |
| K4 | Missing Human Confirmation for Destructive Operations | compliance-governance | high | Y |  |  | 0 | — | — |
| K5 | Auto-Approve / Bypass Confirmation Pattern | compliance-governance | critical | Y |  |  | 0 | — | — |
| K6 | Overly Broad OAuth Scopes | compliance-governance | high | Y |  |  | 0 | — | — |
| K7 | Long-Lived Tokens Without Rotation | compliance-governance | high | Y |  |  | 0 | — | — |
| K8 | Cross-Boundary Credential Sharing | compliance-governance | critical | Y |  |  | 0 | — | — |
| K9 | Dangerous Post-Install Hooks | compliance-governance | critical | Y |  |  | 0 | — | — |
| K10 | Package Registry Substitution | compliance-governance | high | Y |  |  | 0 | — | — |
| K11 | Missing Server Integrity Verification | compliance-governance | high | Y |  |  | 0 | — | — |
| K12 | Executable Content in Tool Response | compliance-governance | critical | Y |  |  | 0 | — | — |
| K13 | Unsanitized Tool Output | compliance-governance | high | Y |  |  | 0 | — | — |
| K14 | Agent Credential Propagation via Shared State | compliance-governance | critical | Y |  |  | 0 | — | — |
| K15 | Multi-Agent Collusion Preconditions | compliance-governance | high | Y |  |  | 0 | — | — |
| K16 | Unbounded Recursion / Missing Depth Limits | compliance-governance | high | Y |  |  | 0 | — | — |
| K17 | Missing Timeout or Circuit Breaker | compliance-governance | medium | Y |  |  | 0 | — | — |
| K18 | Cross-Trust-Boundary Data Flow in Tool Response | compliance-governance | high | Y |  |  | 0 | — | — |
| K19 | Missing Runtime Sandbox Enforcement | compliance-governance | high | Y |  |  | 0 | — | — |
| K20 | Insufficient Audit Context in Logging | compliance-governance | medium | Y |  |  | 0 | — | — |
| L1 | GitHub Actions Tag Poisoning | supply-chain-advanced | critical | Y |  |  | 0 | — | — |
| L2 | Malicious Build Plugin Injection | supply-chain-advanced | critical | Y |  |  | 0 | — | — |
| L3 | Dockerfile Base Image Supply Chain Risk | supply-chain-advanced | high | Y |  |  | 0 | — | — |
| L4 | MCP Config File Code Injection | supply-chain-advanced | critical | Y |  |  | 0 | — | — |
| L5 | Package Manifest Confusion Indicators | supply-chain-advanced | high | Y |  |  | 0 | — | — |
| L6 | Config Directory Symlink Attack | supply-chain-advanced | critical | Y |  |  | 0 | — | — |
| L7 | Transitive MCP Server Delegation | supply-chain-advanced | critical | Y |  |  | 0 | — | — |
| L8 | Version Rollback / Downgrade Attack | supply-chain-advanced | high | Y |  | Y | 17 | v | `l-supply-chain-v2.ts` |
| L9 | CI/CD Secret Exfiltration Patterns | supply-chain-advanced | critical | Y |  |  | 0 | — | — |
| L10 | Registry Metadata Spoofing | supply-chain-advanced | high | Y |  | Y | 17 | v | `l-supply-chain-v2.ts` |
| L11 | Environment Variable Injection via MCP Config | supply-chain-advanced | critical | Y |  |  | 0 | — | — |
| L12 | Build Artifact Tampering | supply-chain-advanced | critical | Y |  |  | 0 | — | — |
| L13 | Build Credential File Theft | supply-chain-advanced | critical | Y |  |  | 0 | — | — |
| L14 | Hidden Entry Point Mismatch | supply-chain-advanced | high | Y |  |  | 0 | — | — |
| L15 | Update Notification Spoofing | supply-chain-advanced | high | Y |  | Y | 17 | v | `l-supply-chain-v2.ts` |
| M1 | Special Token Injection in Tool Metadata | ai-runtime-exploitation | critical | Y | Y |  | 33 | v | `protocol-ai-runtime-detector.ts` |
| M2 | TokenBreak Boundary Manipulation | ai-runtime-exploitation | high | Y |  | Y | 43 | v | `m-runtime-v2.ts` |
| M3 | Reasoning Chain Manipulation | ai-runtime-exploitation | critical | N | Y |  | 33 | v | `protocol-ai-runtime-detector.ts` |
| M4 | Reasoning Loop Induction | ai-runtime-exploitation | high | Y |  | Y | 9 | v | `m4-tool-squatting.ts` |
| M5 | Tool Position Bias Exploitation | ai-runtime-exploitation | high | Y |  | Y | 11 | v | `m5-context-window-flooding.ts` |
| M6 | Progressive Context Poisoning Enablers | ai-runtime-exploitation | critical | Y | Y |  | 33 | v | `protocol-ai-runtime-detector.ts` |
| M7 | Tool Response Structure Bomb | ai-runtime-exploitation | high | Y |  | Y | 43 | v | `m-runtime-v2.ts` |
| M8 | Inference Cost Amplification | ai-runtime-exploitation | high | Y |  | Y | 43 | v | `m-runtime-v2.ts` |
| M9 | Model-Specific System Prompt Extraction | ai-runtime-exploitation | critical | Y | Y |  | 33 | v | `protocol-ai-runtime-detector.ts` |
| N1 | JSON-RPC Batch Request Abuse | protocol-edge-cases | high | Y |  |  | 0 | — | — |
| N2 | JSON-RPC Notification Flooding | protocol-edge-cases | high | Y |  |  | 0 | — | — |
| N3 | JSON-RPC Request ID Collision | protocol-edge-cases | high | Y |  |  | 0 | — | — |
| N4 | JSON-RPC Error Object Injection | protocol-edge-cases | critical | Y | Y |  | 33 | v | `protocol-ai-runtime-detector.ts` |
| N5 | Capability Downgrade Deception | protocol-edge-cases | critical | Y | Y |  | 33 | v | `protocol-ai-runtime-detector.ts` |
| N6 | SSE Reconnection Hijacking | protocol-edge-cases | critical | Y | Y |  | 33 | v | `protocol-ai-runtime-detector.ts` |
| N7 | Progress Token Prediction and Injection | protocol-edge-cases | high | Y |  |  | 0 | — | — |
| N8 | Cancellation Race Condition | protocol-edge-cases | high | Y |  |  | 0 | — | — |
| N9 | MCP Logging Protocol Injection | protocol-edge-cases | critical | Y | Y |  | 33 | v | `protocol-ai-runtime-detector.ts` |
| N10 | Incomplete Handshake Denial of Service | protocol-edge-cases | high | Y |  |  | 0 | — | — |
| N11 | Protocol Version Downgrade Attack | protocol-edge-cases | critical | Y | Y |  | 33 | v | `protocol-ai-runtime-detector.ts` |
| N12 | Resource Subscription Content Mutation | protocol-edge-cases | critical | Y | Y |  | 33 | v | `protocol-ai-runtime-detector.ts` |
| N13 | HTTP Chunked Transfer Smuggling | protocol-edge-cases | critical | Y | Y |  | 33 | v | `protocol-ai-runtime-detector.ts` |
| N14 | Trust-On-First-Use Bypass (TOFU) | protocol-edge-cases | critical | Y | Y |  | 33 | v | `protocol-ai-runtime-detector.ts` |
| N15 | JSON-RPC Method Name Confusion | protocol-edge-cases | critical | Y | Y |  | 33 | v | `protocol-ai-runtime-detector.ts` |
| O1 | Steganographic Data Exfiltration | data-privacy-attacks | critical | N | Y |  | 38 | av | `data-privacy-cross-ecosystem-detector.ts` |
| O2 | HTTP Header Covert Channel | data-privacy-attacks | critical | N | Y |  | 38 | av | `data-privacy-cross-ecosystem-detector.ts` |
| O3 | AI-Mediated Exfiltration via Tool Arguments | data-privacy-attacks | critical | N | Y |  | 38 | av | `data-privacy-cross-ecosystem-detector.ts` |
| O4 | Clipboard and UI Exfiltration Injection | data-privacy-attacks | high | Y |  | Y | 23 | v | `o4-q10-v2.ts` |
| O5 | Environment Variable Harvesting | data-privacy-attacks | critical | Y | Y |  | 38 | av | `data-privacy-cross-ecosystem-detector.ts` |
| O6 | Server Fingerprinting via Error Responses | data-privacy-attacks | high | Y | Y |  | 7 | v | `compliance-remaining-detector.ts` |
| O7 | Cross-Session Data Leakage | data-privacy-attacks | critical | N | Y |  | 38 | av | `data-privacy-cross-ecosystem-detector.ts` |
| O8 | Timing-Based Covert Channel | data-privacy-attacks | high | Y | Y |  | 7 | v | `compliance-remaining-detector.ts` |
| O9 | Ambient Credential Exploitation | data-privacy-attacks | critical | Y | Y |  | 38 | av | `data-privacy-cross-ecosystem-detector.ts` |
| O10 | Privacy-Violating Telemetry | data-privacy-attacks | high | Y | Y |  | 7 | v | `compliance-remaining-detector.ts` |
| P1 | Docker Socket Mount in Container | infrastructure-runtime | critical | Y |  |  | 0 | — | — |
| P2 | Dangerous Container Capabilities | infrastructure-runtime | critical | Y |  |  | 0 | — | — |
| P3 | Cloud Metadata Service Access | infrastructure-runtime | critical | Y |  |  | 0 | — | — |
| P4 | TLS Certificate Validation Bypass | infrastructure-runtime | critical | Y |  |  | 0 | — | — |
| P5 | Secrets Exposed in Container Build Layers | infrastructure-runtime | critical | Y |  |  | 0 | — | — |
| P6 | LD_PRELOAD and Shared Library Hijacking | infrastructure-runtime | critical | Y |  |  | 0 | — | — |
| P7 | Sensitive Host Filesystem Mount | infrastructure-runtime | critical | Y |  |  | 0 | — | — |
| P8 | Insecure Cryptographic Mode or Static IV/Nonce | infrastructure-runtime | high | Y |  |  | 0 | — | — |
| P9 | Missing Container Resource Limits | infrastructure-runtime | high | Y |  |  | 0 | — | — |
| P10 | Host Network Mode and Missing Egress Controls | infrastructure-runtime | high | Y |  |  | 0 | — | — |
| Q1 | Dual-Protocol Schema Constraint Loss | cross-ecosystem-emergent | critical | N | Y |  | 38 | av | `data-privacy-cross-ecosystem-detector.ts` |
| Q2 | LangChain Serialization Bridge Injection | cross-ecosystem-emergent | critical | N | Y |  | 38 | av | `data-privacy-cross-ecosystem-detector.ts` |
| Q3 | Localhost MCP Service Hijacking | cross-ecosystem-emergent | critical | Y | Y |  | 38 | av | `data-privacy-cross-ecosystem-detector.ts` |
| Q4 | IDE MCP Configuration Injection | cross-ecosystem-emergent | critical | Y |  |  | 0 | — | — |
| Q5 | MCP Gateway Trust Delegation Confusion | cross-ecosystem-emergent | critical | N | Y |  | 38 | av | `data-privacy-cross-ecosystem-detector.ts` |
| Q6 | Agent Identity Impersonation via MCP | cross-ecosystem-emergent | critical | Y | Y |  | 38 | av | `data-privacy-cross-ecosystem-detector.ts` |
| Q7 | Desktop Extension Privilege Chain | cross-ecosystem-emergent | critical | Y | Y |  | 38 | av | `data-privacy-cross-ecosystem-detector.ts` |
| Q8 | Cross-Protocol Authentication Confusion | cross-ecosystem-emergent | critical | N | Y |  | 38 | av | `data-privacy-cross-ecosystem-detector.ts` |
| Q9 | Agentic Workflow DAG Manipulation | cross-ecosystem-emergent | critical | N | Y |  | 38 | av | `data-privacy-cross-ecosystem-detector.ts` |
| Q10 | Multi-Server Capability Composition Attack | cross-ecosystem-emergent | high | Y |  | Y | 23 | v | `o4-q10-v2.ts` |
| Q11 | Code Suggestion Poisoning via MCP | cross-ecosystem-emergent | critical | N | Y |  | 38 | av | `data-privacy-cross-ecosystem-detector.ts` |
| Q12 | Cross-Jurisdiction Data Routing via MCP | cross-ecosystem-emergent | high | N | Y |  | 7 | v | `compliance-remaining-detector.ts` |
| Q13 | MCP Bridge Package Supply Chain Attack | cross-ecosystem-emergent | critical | Y | Y |  | 38 | av | `data-privacy-cross-ecosystem-detector.ts` |
| Q14 | Concurrent MCP Server Race Condition | cross-ecosystem-emergent | high | N | Y |  | 7 | v | `compliance-remaining-detector.ts` |
| Q15 | A2A/MCP Protocol Boundary Confusion | cross-ecosystem-emergent | high | Y | Y |  | 7 | v | `compliance-remaining-detector.ts` |

## Notes

- **A1**: enabled in YAML but no TypedRule registration found
- **A2**: enabled in YAML but no TypedRule registration found
- **A3**: enabled in YAML but no TypedRule registration found
- **A4**: enabled in YAML but no TypedRule registration found
- **A5**: enabled in YAML but no TypedRule registration found
- **A6**: enabled in YAML but no TypedRule registration found
- **A7**: enabled in YAML but no TypedRule registration found
- **A8**: enabled in YAML but no TypedRule registration found
- **A9**: enabled in YAML but no TypedRule registration found
- **B1**: enabled in YAML but no TypedRule registration found
- **B2**: enabled in YAML but no TypedRule registration found
- **B3**: enabled in YAML but no TypedRule registration found
- **B4**: enabled in YAML but no TypedRule registration found
- **B5**: enabled in YAML but no TypedRule registration found
- **B6**: enabled in YAML but no TypedRule registration found
- **B7**: enabled in YAML but no TypedRule registration found
- **C1**: enabled in YAML but no TypedRule registration found
- **C2**: enabled in YAML but no TypedRule registration found
- **C3**: enabled in YAML but no TypedRule registration found
- **C4**: enabled in YAML but no TypedRule registration found
- **C5**: enabled in YAML but no TypedRule registration found
- **C6**: enabled in YAML but no TypedRule registration found
- **C7**: enabled in YAML but no TypedRule registration found
- **C8**: enabled in YAML but no TypedRule registration found
- **C9**: enabled in YAML but no TypedRule registration found
- **C10**: enabled in YAML but no TypedRule registration found
- **C11**: enabled in YAML but no TypedRule registration found
- **C12**: enabled in YAML but no TypedRule registration found
- **C13**: enabled in YAML but no TypedRule registration found
- **C14**: enabled in YAML but no TypedRule registration found
- **C15**: enabled in YAML but no TypedRule registration found
- **C16**: enabled in YAML but no TypedRule registration found
- **D1**: enabled in YAML but no TypedRule registration found
- **D2**: enabled in YAML but no TypedRule registration found
- **D3**: enabled in YAML but no TypedRule registration found
- **D4**: enabled in YAML but no TypedRule registration found
- **D5**: enabled in YAML but no TypedRule registration found
- **D6**: enabled in YAML but no TypedRule registration found
- **D7**: enabled in YAML but no TypedRule registration found
- **E1**: enabled in YAML but no TypedRule registration found
- **E2**: enabled in YAML but no TypedRule registration found
- **E3**: enabled in YAML but no TypedRule registration found
- **E4**: enabled in YAML but no TypedRule registration found
- **F1**: enabled in YAML but no TypedRule registration found
- **F2**: enabled in YAML but no TypedRule registration found
- **F3**: enabled in YAML but no TypedRule registration found
- **F4**: enabled in YAML but no TypedRule registration found
- **F5**: enabled in YAML but no TypedRule registration found
- **F6**: enabled in YAML but no TypedRule registration found
- **F7**: enabled in YAML but no TypedRule registration found
- **G1**: enabled in YAML but no TypedRule registration found
- **G2**: enabled in YAML but no TypedRule registration found
- **G3**: enabled in YAML but no TypedRule registration found
- **G4**: enabled in YAML but no TypedRule registration found
- **G5**: enabled in YAML but no TypedRule registration found
- **G6**: enabled in YAML but no TypedRule registration found
- **G7**: enabled in YAML but no TypedRule registration found
- **H1**: enabled in YAML but no TypedRule registration found
- **H2**: enabled in YAML but no TypedRule registration found
- **H3**: enabled in YAML but no TypedRule registration found
- **J1**: enabled in YAML but no TypedRule registration found
- **J2**: enabled in YAML but no TypedRule registration found
- **K1**: enabled in YAML but no TypedRule registration found
- **K2**: enabled in YAML but no TypedRule registration found
- **K3**: enabled in YAML but no TypedRule registration found
- **K4**: enabled in YAML but no TypedRule registration found
- **K5**: enabled in YAML but no TypedRule registration found
- **K6**: enabled in YAML but no TypedRule registration found
- **K7**: enabled in YAML but no TypedRule registration found
- **K8**: enabled in YAML but no TypedRule registration found
- **K9**: enabled in YAML but no TypedRule registration found
- **K10**: enabled in YAML but no TypedRule registration found
- **K11**: enabled in YAML but no TypedRule registration found
- **K12**: enabled in YAML but no TypedRule registration found
- **K13**: enabled in YAML but no TypedRule registration found
- **K14**: enabled in YAML but no TypedRule registration found
- **K15**: enabled in YAML but no TypedRule registration found
- **K16**: enabled in YAML but no TypedRule registration found
- **K17**: enabled in YAML but no TypedRule registration found
- **K18**: enabled in YAML but no TypedRule registration found
- **K19**: enabled in YAML but no TypedRule registration found
- **K20**: enabled in YAML but no TypedRule registration found
- **L1**: enabled in YAML but no TypedRule registration found
- **L2**: enabled in YAML but no TypedRule registration found
- **L3**: enabled in YAML but no TypedRule registration found
- **L4**: enabled in YAML but no TypedRule registration found
- **L5**: enabled in YAML but no TypedRule registration found
- **L6**: enabled in YAML but no TypedRule registration found
- **L7**: enabled in YAML but no TypedRule registration found
- **L9**: enabled in YAML but no TypedRule registration found
- **L11**: enabled in YAML but no TypedRule registration found
- **L12**: enabled in YAML but no TypedRule registration found
- **L13**: enabled in YAML but no TypedRule registration found
- **L14**: enabled in YAML but no TypedRule registration found
- **M3**: disabled in YAML but still registered
- **N1**: enabled in YAML but no TypedRule registration found
- **N2**: enabled in YAML but no TypedRule registration found
- **N3**: enabled in YAML but no TypedRule registration found
- **N7**: enabled in YAML but no TypedRule registration found
- **N8**: enabled in YAML but no TypedRule registration found
- **N10**: enabled in YAML but no TypedRule registration found
- **O1**: disabled in YAML but still registered
- **O2**: disabled in YAML but still registered
- **O3**: disabled in YAML but still registered
- **O7**: disabled in YAML but still registered
- **P1**: enabled in YAML but no TypedRule registration found
- **P2**: enabled in YAML but no TypedRule registration found
- **P3**: enabled in YAML but no TypedRule registration found
- **P4**: enabled in YAML but no TypedRule registration found
- **P5**: enabled in YAML but no TypedRule registration found
- **P6**: enabled in YAML but no TypedRule registration found
- **P7**: enabled in YAML but no TypedRule registration found
- **P8**: enabled in YAML but no TypedRule registration found
- **P9**: enabled in YAML but no TypedRule registration found
- **P10**: enabled in YAML but no TypedRule registration found
- **Q1**: disabled in YAML but still registered
- **Q2**: disabled in YAML but still registered
- **Q4**: enabled in YAML but no TypedRule registration found
- **Q5**: disabled in YAML but still registered
- **Q8**: disabled in YAML but still registered
- **Q9**: disabled in YAML but still registered
- **Q11**: disabled in YAML but still registered
- **Q12**: disabled in YAML but still registered
- **Q14**: disabled in YAML but still registered
