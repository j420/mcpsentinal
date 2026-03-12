# MCP Sentinel — Detection Rules Specification
## P8 Detection Rule Engineer Output — v1.0

### Rule Categories

| Category | Code | Requires Source Code | Rule Count |
|----------|------|---------------------|------------|
| Description Analysis | A | No | 5 |
| Schema Analysis | B | No | 4 |
| Code Analysis | C | Yes | 9 |
| Dependency Analysis | D | Yes (package manifest) | 4 |
| Behavioral Analysis | E | No (connection metadata) | 4 |
| Ecosystem Context | F | No (tool metadata) | 4 |

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
| MCP01 | Prompt Injection | A1, A5, F1 |
| MCP02 | Tool Poisoning | A2, A4, F2 |
| MCP03 | Command Injection | C1, C9 |
| MCP04 | Data Exfiltration | F1, F3 |
| MCP05 | Privilege Escalation | C2, C8 |
| MCP06 | Excessive Permissions | A2, B3, E4, F2 |
| MCP07 | Insecure Configuration | C7, C8, E1, E2 |
| MCP08 | Dependency Vulnerabilities | D1, D2, D3, D4 |
| MCP09 | Logging & Monitoring | C6, E3 |
| MCP10 | Supply Chain | D3, A4 |

### Rule Definitions

See `rules/*.yaml` for complete rule definitions with test cases.

### Section F: Dynamic Tool Invocation

Dynamic tool invocation (actually calling MCP server tools with test inputs) is a GATED capability:
- Not enabled in v1.0 scanning
- Requires explicit opt-in from server authors
- All test inputs are read-only canary values
- Full audit log of all invocations
- See P10 (Red Team) for the dynamic testing methodology
