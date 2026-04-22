---
rule_id: J4
interface_version: v2
severity: high

threat_refs:
  - kind: cve
    id: CVE-2026-29787
    url: https://nvd.nist.gov/vuln/detail/CVE-2026-29787
    summary: >
      mcp-memory-service exposed /health/detailed leaking OS, CPU,
      memory, database connection info, and environment variables
      without authentication. Canonical precedent for the J4 rule.
  - kind: spec
    id: OWASP-Information-Exposure
    url: https://owasp.org/www-community/Improper_Error_Handling
    summary: >
      OWASP Improper Error Handling / Information Exposure. MCP
      servers that leave development-time health/debug endpoints on
      the production build expose reconnaissance data that greatly
      accelerates attacker enumeration.

lethal_edge_cases:
  - >
    /health/detailed endpoint returning OS version, CPU count,
    memory, disk paths, env vars. Exact CVE-2026-29787 pattern.
  - >
    /debug endpoint returning stack traces, state dumps, or
    database connection strings.
  - >
    /metrics endpoint returning internal counters, per-route latency,
    and per-client usage patterns.
  - >
    /info endpoint returning build / version / feature-flag info
    attackers use for exploit targeting.
  - >
    /status/full returning the full server state dump including
    feature-flag evaluations that leak tenant/customer data.

edge_case_strategies:
  - endpoint-catalogue-match
  - unauth-exposure-warning
  - severity-tier-from-catalogue
  - cve-precedent-reference
  - false-positive-fence-demotion

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - health_debug_endpoint_matched
    - charter_confidence_cap
  location_kinds:
    - source

obsolescence:
  retire_when: >
    MCP server frameworks strip health/debug/metrics endpoints from
    production builds by default AND require explicit opt-in with
    authentication.
---

# J4 — Health Endpoint Information Disclosure

Uses the shared `HEALTH_DEBUG_ENDPOINTS` catalogue. Confidence cap
**0.92** — endpoint path is exact-match boolean.
