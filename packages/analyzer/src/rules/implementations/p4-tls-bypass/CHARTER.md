---
rule_id: P4
interface_version: v2
severity: critical
owasp: MCP07-insecure-config
mitre: AML.T0054
risk_domain: container-runtime

threat_refs:
  - kind: spec
    id: CWE-295
    url: https://cwe.mitre.org/data/definitions/295.html
    summary: >
      CWE-295 "Improper Certificate Validation" is the parent weakness
      behind every TLS-bypass pattern this rule detects. The CWE catalog
      specifically lists the Node.js rejectUnauthorized:false pattern,
      the Python requests verify=False pattern, and the Go
      InsecureSkipVerify pattern as the canonical bad examples. An MCP
      server with ANY of these patterns accepts man-in-the-middle
      certificates on every outbound connection.
  - kind: spec
    id: OWASP-TLS-Cheat-Sheet
    url: https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html
    summary: >
      OWASP TLS Cheat Sheet §Certificate-Validation explicitly states
      that disabling certificate verification "should be treated as a
      vulnerability" regardless of the justification offered (self-
      signed certs, internal CAs, development convenience). The cheat
      sheet provides concrete remediation: pin the trusted CA via
      NODE_EXTRA_CA_CERTS / requests.Session(verify="/path/ca.pem") /
      tls.Config{RootCAs:}, never disable validation.

lethal_edge_cases:
  - >
    Environment-variable form — `process.env.NODE_TLS_REJECT_UNAUTHORIZED
    = "0"` disables TLS verification for the entire Node.js process,
    effectively affecting every library downstream. A rule that only
    checks for `rejectUnauthorized: false` object literals misses this
    much more dangerous global-override form.
  - >
    Agent-level form — `new https.Agent({ rejectUnauthorized: false })`
    where the agent is then passed to any fetch / request call. The
    rejectUnauthorized key is inside a constructor call, not a request
    options object — a shallow pattern miss. The rule must recognise
    the Agent / HttpsAgent / Agent constructor forms.
  - >
    Python InsecureRequestWarning suppression — `urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning)` combined with verify=False
    elsewhere. A rule flagging the warning-suppression call alone is
    noisy, but the COMBINATION is a strong signal of intentional TLS
    bypass with stealth. The rule flags verify=False on its own and
    uses the warning suppression as an amplifier.
  - >
    Downgrade to HTTP — code that conditionally uses `http://` for
    internal-network traffic is an implicit TLS bypass. A flag like
    `if (internal) url = url.replace("https:", "http:")` is harder to
    detect but equivalent in posture. The rule flags explicit scheme
    swaps combined with a fetch / request sink.
  - >
    curl --insecure / wget --no-check-certificate in build scripts —
    Dockerfiles that download artefacts with --insecure / --no-check-
    certificate during build bake untrusted content into the image
    layer. A rule that only scans runtime TLS settings misses build-
    time TLS bypass. Every CLI tool that has a "skip certificate check"
    flag (curl, wget, git, npm, pip) is a potential variant.

edge_case_strategies:
  - environment-variable-global-override
  - agent-constructor-detection
  - python-warning-suppression
  - scheme-downgrade-detection
  - build-script-cli-flags

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - bypass_variant
    - language_family
    - global_scope_impact
  location_kinds:
    - source
    - config

obsolescence:
  retire_when: >
    Node.js removes support for NODE_TLS_REJECT_UNAUTHORIZED AND Python
    removes the verify=False ergonomic. Both are long-standing "do not
    use" flags with wide ecosystem pressure to deprecate, but not yet
    removed. Until then this rule is a front-line TLS posture control.
---

# P4 — TLS Certificate Validation Bypass

**Author:** Senior MCP Infrastructure Security Engineer persona.
**Applies to:** TypeScript / JavaScript / Python / Go / Java / shell
source files that disable TLS certificate verification, configure an
HTTP agent with verification disabled, suppress InsecureRequestWarning,
or call CLI tools with --insecure / --no-check-certificate flags.

## What an auditor accepts as evidence

A CWE-295 / OWASP TLS-Cheat-Sheet auditor wants:

1. **Scope proof** — specific language / library / variant and a
   `source`-kind Location at the file and line that establishes the
   bypass. The rule reports one finding per distinct bypass site.

2. **Gap proof** — the observed pattern defeats certificate validation
   for at least one outbound connection. For the NODE_TLS_REJECT_
   UNAUTHORIZED=0 variant, the rule notes that this is process-wide
   (every downstream HTTPS call is affected).

3. **Impact statement** — concrete MITM scenario on any co-located
   attacker who can intercept traffic (shared Wi-Fi, compromised
   upstream network device, or cross-container ARP spoof).

## What the rule does NOT claim

- It does not verify whether a specific internal-CA configuration
  would have made the bypass unnecessary — the correct remediation is
  pinning, but the analyzer cannot observe the internal-CA posture.
- It does not distinguish development-only code paths unless the
  bypass is gated on NODE_ENV / an obvious test-only flag; ambiguous
  cases produce a standalone finding.

## Why confidence is capped at 0.85

TLS-bypass patterns are unambiguous in source; the uncertainty is
whether the code path is reachable in production. Development-only
debug scripts genuinely sometimes carry these flags. 0.85 preserves
room for that without suppressing the posture finding.
