# Rule Census

_Generated: 2026-04-21T11:47:58.829Z_

## Summary

| Metric | Value |
|---|---|
| YAML rules (total) | 177 |
| YAML rules (enabled) | 164 |
| Registered rules (unique ids) | 159 |
| Registered v1 | 132 |
| Registered v2 | 27 |
| Enabled but unregistered | 18 |
| Detector files | 27 |
| Files with any regex | 24 |
| Files with any technique import | 14 |

## Aggregate Technique Observations

| Signal | Count |
|---|---|
| Regex literals | 709 |
| new RegExp(...) calls | 3 |
| String-literal arrays > 5 | 7 |
| Rules using taint-ast | 49 |
| Rules using capability-graph | 36 |
| Rules using module-graph | 0 |
| Rules using entropy | 5 |
| Rules using similarity | 15 |
| Rules using EvidenceChainBuilder | 159 |

## Top Regex Offenders (detector files)

| File | Regex literals | new RegExp calls |
|---|---:|---:|
| `packages/analyzer/src/rules/implementations/jsonrpc-protocol-v2.ts` | 64 | 0 |
| `packages/analyzer/src/rules/implementations/docker-k8s-crypto-v2.ts` | 47 | 0 |
| `packages/analyzer/src/rules/implementations/config-poisoning-detector.ts` | 44 | 1 |
| `packages/analyzer/src/rules/implementations/infrastructure-detector.ts` | 44 | 0 |
| `packages/analyzer/src/rules/implementations/m-runtime-v2.ts` | 43 | 0 |
| `packages/analyzer/src/rules/implementations/data-privacy-cross-ecosystem-detector.ts` | 38 | 0 |
| `packages/analyzer/src/rules/implementations/advanced-supply-chain-detector.ts` | 36 | 0 |
| `packages/analyzer/src/rules/implementations/k-compliance-v2.ts` | 36 | 0 |
| `packages/analyzer/src/rules/implementations/k-remaining-v2.ts` | 36 | 0 |
| `packages/analyzer/src/rules/implementations/code-security-deep-detector.ts` | 35 | 0 |

## Per-Rule Detail

Columns: enabled (E), v1 registered (1), v2 registered (2), regex count (R), analyzer toolkit (T).
T = first-letter tags: a=ast-taint, c=capability-graph, m=module-graph, e=entropy, s=similarity, i=schema-inference, v=EvidenceChainBuilder.

> _Registration harvest caveat: for detectors of the form_ `for (cfg of RULES) registerTypedRule(buildRule(cfg))`, _the census credits every config object with an `id:` property, even if the runtime loop filters some out. Regex counts and toolkit imports are exact._

| ID | Name | Cat | Sev | E | 1 | 2 | R | T | Detector |
|---|---|---|---|:-:|:-:|:-:|---:|---|---|
| A1 | Prompt Injection in Tool Description | description-analysis | critical | Y | Y |  | 29 | v | `description-schema-detector.ts` |
| A2 | Excessive Scope Claims in Description | description-analysis | high | Y | Y |  | 29 | v | `description-schema-detector.ts` |
| A3 | Suspicious URLs in Tool Description | description-analysis | medium | Y | Y |  | 29 | v | `description-schema-detector.ts` |
| A4 | Cross-Server Tool Name Shadowing | description-analysis | high | Y | Y |  | 29 | v | `description-schema-detector.ts` |
| A5 | Description Length Anomaly | description-analysis | low | Y | Y |  | 29 | v | `description-schema-detector.ts` |
| A6 | Unicode Homoglyph Attack in Tool Name or Description | description-analysis | critical | Y |  |  | 0 | — | — |
| A7 | Zero-Width and Invisible Character Injection | description-analysis | critical | Y |  |  | 0 | — | — |
| A8 | Description-Capability Mismatch (Read-Only Claim with Write Parameters) | description-analysis | high | Y | Y |  | 29 | v | `description-schema-detector.ts` |
| A9 | Encoded or Obfuscated Instructions in Tool Description | description-analysis | critical | Y |  |  | 0 | — | — |
| B1 | Missing Input Validation | schema-analysis | medium | Y | Y |  | 29 | v | `description-schema-detector.ts` |
| B2 | Dangerous Parameter Types | schema-analysis | high | Y | Y |  | 29 | v | `description-schema-detector.ts` |
| B3 | Excessive Parameter Count | schema-analysis | low | Y | Y |  | 29 | v | `description-schema-detector.ts` |
| B4 | Schema-less Tool | schema-analysis | medium | Y | Y |  | 29 | v | `description-schema-detector.ts` |
| B5 | Prompt Injection in Parameter Description | schema-analysis | critical | Y | Y |  | 29 | v | `description-schema-detector.ts` |
| B6 | Schema Allows Unconstrained Additional Properties | schema-analysis | medium | Y | Y |  | 29 | v | `description-schema-detector.ts` |
| B7 | Dangerous Default Parameter Values | schema-analysis | high | Y | Y |  | 29 | v | `description-schema-detector.ts` |
| C1 | Command Injection | code-analysis | critical | Y |  |  | 0 | — | — |
| C2 | Path Traversal | code-analysis | critical | Y | Y |  | 35 | aev | `code-security-deep-detector.ts` |
| C3 | Server-Side Request Forgery (SSRF) | code-analysis | high | Y | Y |  | 19 | av | `code-remaining-detector.ts` |
| C4 | SQL Injection | code-analysis | critical | Y |  |  | 0 | — | — |
| C5 | Hardcoded Secrets in Source Code | code-analysis | critical | Y | Y |  | 35 | aev | `code-security-deep-detector.ts` |
| C6 | Error Message Information Leakage | code-analysis | medium | Y | Y |  | 19 | av | `code-remaining-detector.ts` |
| C7 | Wildcard CORS Configuration | code-analysis | high | Y | Y |  | 19 | av | `code-remaining-detector.ts` |
| C8 | No Authentication on Network-Exposed Server | code-analysis | high | Y | Y |  | 19 | av | `code-remaining-detector.ts` |
| C9 | Excessive Filesystem Scope | code-analysis | high | Y | Y |  | 19 | av | `code-remaining-detector.ts` |
| C10 | Prototype Pollution | code-analysis | critical | Y | Y |  | 35 | aev | `code-security-deep-detector.ts` |
| C11 | ReDoS — Catastrophic Regex Backtracking | code-analysis | high | Y | Y |  | 19 | av | `code-remaining-detector.ts` |
| C12 | Unsafe Deserialization | code-analysis | critical | Y |  |  | 0 | — | — |
| C13 | Server-Side Template Injection (SSTI) | code-analysis | critical | Y |  |  | 0 | — | — |
| C14 | JWT Algorithm Confusion / None Algorithm Attack | code-analysis | critical | Y | Y |  | 35 | aev | `code-security-deep-detector.ts` |
| C15 | Timing Attack on Secret or Token Comparison | code-analysis | high | Y | Y |  | 19 | av | `code-remaining-detector.ts` |
| C16 | Dynamic Code Evaluation with User Input | code-analysis | critical | Y |  |  | 0 | — | — |
| D1 | Known CVEs in Dependencies | dependency-analysis | high | Y | Y |  | 0 | sv | `dependency-behavioral-detector.ts` |
| D2 | Abandoned Dependencies | dependency-analysis | medium | Y | Y |  | 0 | sv | `dependency-behavioral-detector.ts` |
| D3 | Typosquatting Risk in Dependencies | dependency-analysis | high | Y |  |  | 0 | — | — |
| D4 | Excessive Dependency Count | dependency-analysis | low | Y | Y |  | 0 | sv | `dependency-behavioral-detector.ts` |
| D5 | Known Malicious or Flagged Package | dependency-analysis | critical | Y | Y |  | 0 | sv | `dependency-behavioral-detector.ts` |
| D6 | Weak or Deprecated Cryptography Dependencies | dependency-analysis | high | Y | Y |  | 0 | sv | `dependency-behavioral-detector.ts` |
| D7 | Dependency Confusion Attack Risk | dependency-analysis | high | Y | Y |  | 0 | sv | `dependency-behavioral-detector.ts` |
| E1 | No Authentication Required | behavioral-analysis | medium | Y | Y |  | 0 | sv | `dependency-behavioral-detector.ts` |
| E2 | Insecure Transport | behavioral-analysis | high | Y | Y |  | 0 | sv | `dependency-behavioral-detector.ts` |
| E3 | Response Time Anomaly | behavioral-analysis | low | Y | Y |  | 0 | sv | `dependency-behavioral-detector.ts` |
| E4 | Excessive Tool Count | behavioral-analysis | medium | Y | Y |  | 0 | sv | `dependency-behavioral-detector.ts` |
| F1 | Lethal Trifecta - Private Data + Untrusted Content + External Communication | ecosystem-context | critical | Y | Y |  | 0 | civ | `f1-lethal-trifecta.ts` |
| F2 | High-Risk Capability Profile | ecosystem-context | medium | Y | Y |  | 0 | civ | `f1-lethal-trifecta.ts` |
| F3 | Data Flow Risk - Source to Sink | ecosystem-context | high | Y | Y |  | 0 | civ | `f1-lethal-trifecta.ts` |
| F4 | MCP Spec Non-Compliance | ecosystem-context | low | Y | Y |  | 10 | csv | `ecosystem-adversarial-detector.ts` |
| F5 | Official Namespace Squatting | ecosystem-context | critical | Y | Y |  | 10 | csv | `ecosystem-adversarial-detector.ts` |
| F6 | Circular Data Loop — Persistent Prompt Injection Storage Risk | ecosystem-context | high | Y | Y |  | 0 | civ | `f1-lethal-trifecta.ts` |
| F7 | Multi-Step Exfiltration Chain | ecosystem-context | critical | Y | Y |  | 0 | civ | `f1-lethal-trifecta.ts` |
| G1 | Indirect Prompt Injection Gateway | adversarial-ai | critical | Y | Y |  | 25 | cv | `ai-manipulation-detector.ts` |
| G2 | Trust Assertion Injection | adversarial-ai | critical | Y | Y |  | 25 | cv | `ai-manipulation-detector.ts` |
| G3 | Tool Response Format Injection | adversarial-ai | critical | Y | Y |  | 25 | cv | `ai-manipulation-detector.ts` |
| G4 | Context Window Saturation Attack | adversarial-ai | high | Y | Y |  | 0 | ev | `g4-context-saturation.ts` |
| G5 | Capability Escalation via Prior Approval Reference | adversarial-ai | critical | Y | Y |  | 25 | cv | `ai-manipulation-detector.ts` |
| G6 | Tool Behavior Drift (Rug Pull Detection) | adversarial-ai | critical | Y | Y |  | 10 | csv | `ecosystem-adversarial-detector.ts` |
| G7 | DNS-Based Data Exfiltration Channel | adversarial-ai | critical | Y | Y |  | 14 | av | `secret-exfil-detector.ts` |
| H1 | MCP OAuth 2.0 Insecure Implementation | auth-analysis | critical | Y | Y |  | 10 | csv | `ecosystem-adversarial-detector.ts` |
| H2 | Prompt Injection in MCP Initialize Response Fields | adversarial-ai | critical | Y | Y |  | 25 | cv | `ai-manipulation-detector.ts` |
| H3 | Multi-Agent Propagation Risk | adversarial-ai | high | Y | Y |  | 10 | csv | `ecosystem-adversarial-detector.ts` |
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
| J1 | Cross-Agent Configuration Poisoning | threat-intelligence | critical | Y | Y |  | 45 | av | `config-poisoning-detector.ts` |
| J2 | Git Argument Injection | threat-intelligence | critical | Y |  |  | 0 | — | — |
| J3 | Full Schema Poisoning | threat-intelligence | critical | Y | Y |  | 33 | cv | `protocol-surface-remaining-detector.ts` |
| J4 | Health Endpoint Information Disclosure | threat-intelligence | high | Y | Y |  | 33 | cv | `protocol-surface-remaining-detector.ts` |
| J5 | Tool Output Poisoning Patterns | threat-intelligence | critical | Y | Y |  | 33 | cv | `protocol-surface-remaining-detector.ts` |
| J6 | Tool Preference Manipulation | threat-intelligence | high | Y | Y |  | 33 | cv | `protocol-surface-remaining-detector.ts` |
| J7 | OpenAPI Specification Field Injection | threat-intelligence | critical | Y | Y |  | 33 | cv | `protocol-surface-remaining-detector.ts` |
| K1 | Absent Structured Logging | compliance-governance | high | Y |  |  | 0 | — | — |
| K2 | Audit Trail Destruction | compliance-governance | critical | Y | Y |  | 14 | av | `secret-exfil-detector.ts` |
| K3 | Audit Log Tampering | compliance-governance | critical | Y | Y |  | 36 | av | `advanced-supply-chain-detector.ts` |
| K4 | Missing Human Confirmation for Destructive Operations | compliance-governance | high | Y |  |  | 0 | — | — |
| K5 | Auto-Approve / Bypass Confirmation Pattern | compliance-governance | critical | Y | Y |  | 36 | av | `advanced-supply-chain-detector.ts` |
| K6 | Overly Broad OAuth Scopes | compliance-governance | high | Y |  |  | 0 | — | — |
| K7 | Long-Lived Tokens Without Rotation | compliance-governance | high | Y |  |  | 0 | — | — |
| K8 | Cross-Boundary Credential Sharing | compliance-governance | critical | Y | Y |  | 36 | av | `advanced-supply-chain-detector.ts` |
| K9 | Dangerous Post-Install Hooks | compliance-governance | critical | Y |  |  | 0 | — | — |
| K10 | Package Registry Substitution | compliance-governance | high | Y | Y |  | 35 | v | `supply-chain-detector.ts` |
| K11 | Missing Server Integrity Verification | compliance-governance | high | Y |  |  | 0 | — | — |
| K12 | Executable Content in Tool Response | compliance-governance | critical | Y |  |  | 0 | — | — |
| K13 | Unsanitized Tool Output | compliance-governance | high | Y |  |  | 0 | — | — |
| K14 | Agent Credential Propagation via Shared State | compliance-governance | critical | Y |  |  | 0 | — | — |
| K15 | Multi-Agent Collusion Preconditions | compliance-governance | high | Y |  |  | 0 | — | — |
| K16 | Unbounded Recursion / Missing Depth Limits | compliance-governance | high | Y |  |  | 0 | — | — |
| K17 | Missing Timeout or Circuit Breaker | compliance-governance | medium | Y |  |  | 0 | — | — |
| K18 | Cross-Trust-Boundary Data Flow in Tool Response | compliance-governance | high | Y |  |  | 0 | — | — |
| K19 | Missing Runtime Sandbox Enforcement | compliance-governance | high | Y |  | Y | 47 | v | `docker-k8s-crypto-v2.ts` |
| K20 | Insufficient Audit Context in Logging | compliance-governance | medium | Y |  |  | 0 | — | — |
| L1 | GitHub Actions Tag Poisoning | supply-chain-advanced | critical | Y | Y |  | 36 | av | `advanced-supply-chain-detector.ts` |
| L2 | Malicious Build Plugin Injection | supply-chain-advanced | critical | Y | Y |  | 36 | av | `advanced-supply-chain-detector.ts` |
| L3 | Dockerfile Base Image Supply Chain Risk | supply-chain-advanced | high | Y |  | Y | 47 | v | `docker-k8s-crypto-v2.ts` |
| L4 | MCP Config File Code Injection | supply-chain-advanced | critical | Y | Y |  | 45 | av | `config-poisoning-detector.ts` |
| L5 | Package Manifest Confusion Indicators | supply-chain-advanced | high | Y | Y |  | 35 | v | `supply-chain-detector.ts` |
| L6 | Config Directory Symlink Attack | supply-chain-advanced | critical | Y | Y |  | 36 | av | `advanced-supply-chain-detector.ts` |
| L7 | Transitive MCP Server Delegation | supply-chain-advanced | critical | Y | Y |  | 36 | av | `advanced-supply-chain-detector.ts` |
| L8 | Version Rollback / Downgrade Attack | supply-chain-advanced | high | Y |  | Y | 17 | v | `l-supply-chain-v2.ts` |
| L9 | CI/CD Secret Exfiltration Patterns | supply-chain-advanced | critical | Y | Y |  | 14 | av | `secret-exfil-detector.ts` |
| L10 | Registry Metadata Spoofing | supply-chain-advanced | high | Y |  | Y | 17 | v | `l-supply-chain-v2.ts` |
| L11 | Environment Variable Injection via MCP Config | supply-chain-advanced | critical | Y | Y |  | 45 | av | `config-poisoning-detector.ts` |
| L12 | Build Artifact Tampering | supply-chain-advanced | critical | Y | Y |  | 35 | v | `supply-chain-detector.ts` |
| L13 | Build Credential File Theft | supply-chain-advanced | critical | Y | Y |  | 36 | av | `advanced-supply-chain-detector.ts` |
| L14 | Hidden Entry Point Mismatch | supply-chain-advanced | high | Y | Y |  | 35 | v | `supply-chain-detector.ts` |
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
| N1 | JSON-RPC Batch Request Abuse | protocol-edge-cases | high | Y |  | Y | 64 | v | `jsonrpc-protocol-v2.ts` |
| N2 | JSON-RPC Notification Flooding | protocol-edge-cases | high | Y |  | Y | 64 | v | `jsonrpc-protocol-v2.ts` |
| N3 | JSON-RPC Request ID Collision | protocol-edge-cases | high | Y |  | Y | 64 | v | `jsonrpc-protocol-v2.ts` |
| N4 | JSON-RPC Error Object Injection | protocol-edge-cases | critical | Y | Y |  | 33 | v | `protocol-ai-runtime-detector.ts` |
| N5 | Capability Downgrade Deception | protocol-edge-cases | critical | Y | Y |  | 33 | v | `protocol-ai-runtime-detector.ts` |
| N6 | SSE Reconnection Hijacking | protocol-edge-cases | critical | Y | Y |  | 33 | v | `protocol-ai-runtime-detector.ts` |
| N7 | Progress Token Prediction and Injection | protocol-edge-cases | high | Y |  | Y | 64 | v | `jsonrpc-protocol-v2.ts` |
| N8 | Cancellation Race Condition | protocol-edge-cases | high | Y |  | Y | 64 | v | `jsonrpc-protocol-v2.ts` |
| N9 | MCP Logging Protocol Injection | protocol-edge-cases | critical | Y | Y |  | 33 | v | `protocol-ai-runtime-detector.ts` |
| N10 | Incomplete Handshake Denial of Service | protocol-edge-cases | high | Y |  | Y | 64 | v | `jsonrpc-protocol-v2.ts` |
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
| P1 | Docker Socket Mount in Container | infrastructure-runtime | critical | Y | Y |  | 44 | av | `infrastructure-detector.ts` |
| P2 | Dangerous Container Capabilities | infrastructure-runtime | critical | Y | Y |  | 44 | av | `infrastructure-detector.ts` |
| P3 | Cloud Metadata Service Access | infrastructure-runtime | critical | Y | Y |  | 44 | av | `infrastructure-detector.ts` |
| P4 | TLS Certificate Validation Bypass | infrastructure-runtime | critical | Y | Y |  | 44 | av | `infrastructure-detector.ts` |
| P5 | Secrets Exposed in Container Build Layers | infrastructure-runtime | critical | Y | Y |  | 44 | av | `infrastructure-detector.ts` |
| P6 | LD_PRELOAD and Shared Library Hijacking | infrastructure-runtime | critical | Y | Y |  | 44 | av | `infrastructure-detector.ts` |
| P7 | Sensitive Host Filesystem Mount | infrastructure-runtime | critical | Y | Y |  | 44 | av | `infrastructure-detector.ts` |
| P8 | Insecure Cryptographic Mode or Static IV/Nonce | infrastructure-runtime | high | Y |  | Y | 47 | v | `docker-k8s-crypto-v2.ts` |
| P9 | Missing Container Resource Limits | infrastructure-runtime | high | Y |  | Y | 47 | v | `docker-k8s-crypto-v2.ts` |
| P10 | Host Network Mode and Missing Egress Controls | infrastructure-runtime | high | Y |  | Y | 47 | v | `docker-k8s-crypto-v2.ts` |
| Q1 | Dual-Protocol Schema Constraint Loss | cross-ecosystem-emergent | critical | N | Y |  | 38 | av | `data-privacy-cross-ecosystem-detector.ts` |
| Q2 | LangChain Serialization Bridge Injection | cross-ecosystem-emergent | critical | N | Y |  | 38 | av | `data-privacy-cross-ecosystem-detector.ts` |
| Q3 | Localhost MCP Service Hijacking | cross-ecosystem-emergent | critical | Y | Y |  | 38 | av | `data-privacy-cross-ecosystem-detector.ts` |
| Q4 | IDE MCP Configuration Injection | cross-ecosystem-emergent | critical | Y | Y |  | 45 | av | `config-poisoning-detector.ts` |
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

- **A6**: enabled in YAML but no TypedRule registration found
- **A7**: enabled in YAML but no TypedRule registration found
- **A9**: enabled in YAML but no TypedRule registration found
- **C1**: enabled in YAML but no TypedRule registration found
- **C4**: enabled in YAML but no TypedRule registration found
- **C12**: enabled in YAML but no TypedRule registration found
- **C13**: enabled in YAML but no TypedRule registration found
- **C16**: enabled in YAML but no TypedRule registration found
- **D3**: enabled in YAML but no TypedRule registration found
- **J2**: enabled in YAML but no TypedRule registration found
- **K1**: enabled in YAML but no TypedRule registration found
- **K4**: enabled in YAML but no TypedRule registration found
- **K6**: enabled in YAML but no TypedRule registration found
- **K7**: enabled in YAML but no TypedRule registration found
- **K9**: enabled in YAML but no TypedRule registration found
- **K12**: enabled in YAML but no TypedRule registration found
- **K13**: enabled in YAML but no TypedRule registration found
- **K14**: enabled in YAML but no TypedRule registration found
- **K15**: enabled in YAML but no TypedRule registration found
- **K16**: enabled in YAML but no TypedRule registration found
- **K17**: enabled in YAML but no TypedRule registration found
- **K18**: enabled in YAML but no TypedRule registration found
- **K20**: enabled in YAML but no TypedRule registration found
- **M3**: disabled in YAML but still registered
- **O1**: disabled in YAML but still registered
- **O2**: disabled in YAML but still registered
- **O3**: disabled in YAML but still registered
- **O7**: disabled in YAML but still registered
- **Q1**: disabled in YAML but still registered
- **Q2**: disabled in YAML but still registered
- **Q5**: disabled in YAML but still registered
- **Q8**: disabled in YAML but still registered
- **Q9**: disabled in YAML but still registered
- **Q11**: disabled in YAML but still registered
- **Q12**: disabled in YAML but still registered
- **Q14**: disabled in YAML but still registered
