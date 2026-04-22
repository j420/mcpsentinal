---
rule_id: K3
interface_version: v2
severity: critical
owasp: MCP09-logging-monitoring
mitre: AML.T0054
risk_domain: audit-logging

threat_refs:
  - kind: spec
    id: ISO-27001-A.8.15
    url: https://www.iso.org/standard/82875.html
    summary: >
      ISO/IEC 27001:2022 Annex A Control 8.15 (Logging) requires that
      event logs recording user activities, exceptions, faults and
      information security events be produced, stored, PROTECTED AGAINST
      TAMPERING, and analysed. Read-modify-write on a log file — even
      when the intent is "cleanup" — fails the protected-against-
      tampering clause: the log is no longer a faithful record of events.
  - kind: spec
    id: EU-AI-Act-Art-12
    url: https://eur-lex.europa.eu/eli/reg/2024/1689/oj
    summary: >
      Article 12 of the EU AI Act requires that high-risk AI systems
      "automatically record events ('logs') over the duration of the
      system's lifetime" AND that the logs be traceable. A server that
      rewrites its own audit log in place defeats traceability by
      construction — the log now reflects what the attacker WANTED a
      reviewer to see, not what actually happened.
  - kind: paper
    id: cosai-mcp-t12-2026
    url: https://www.coalitionforsecureai.org/publications/mcp-threat-taxonomy
    summary: >
      CoSAI MCP Threat Taxonomy category T12 (Insufficient Monitoring /
      Log Integrity). The taxonomy is explicit that silent log mutation
      — not just deletion — is the higher-severity half of T12. An
      attacker who can rewrite audit entries can create an alibi while
      leaving the file structure intact, which is strictly worse than a
      missing log file that SIEM can detect at file-size level.
  - kind: cve
    id: CVE-2024-52798
    url: https://nvd.nist.gov/vuln/detail/CVE-2024-52798

lethal_edge_cases:
  - >
    Read-filter-write on the audit file — the server reads the log,
    applies a filter that drops rows matching a pattern, then writes the
    filtered content back. The file still exists and is still parseable,
    but the malicious events are gone. A "was a log file written?"
    checker sees a benign write; the rule must detect the round-trip
    (read → transform → write) on the SAME audit file path.
  - >
    In-place `sed -i` from a build or setup script — a Dockerfile RUN
    line or a post-install hook executes `sed -i 's/malicious/benign/'
    audit.log`. The mutation happens at install time, not runtime, so a
    scanner that only inspects tool handlers misses it. The rule must
    match any literal `sed -i` / `sed -i ''` invocation whose argument
    contains an audit-file substring.
  - >
    Open-for-write (`r+` / `O_RDWR`) on a log path — the code does not
    call readFile at all; it opens the file in read-write mode and seeks
    to the offending offset. No high-level filter is visible, but the
    file mode is diagnostic. The rule must flag `fs.open*(..., "r+")` /
    `fs.openSync` with flag `"r+"` or Python `open(..., "r+")` on a log
    path.
  - >
    Timestamp forgery — the code does not rewrite the content; it calls
    `utimes` / `fs.utimes` / `os.utime` to backdate the log file so the
    file appears to predate the intrusion. This defeats time-based
    forensics (which would otherwise correlate the log's mtime with an
    external event) without visibly altering any line.
  - >
    Legitimate PII redaction looks almost identical — a GDPR-compliant
    pipeline that redacts a name field before writing to the persisted
    log is NOT K3. The rule must exclude lines whose surrounding
    comment, function name, or containing block references "redact",
    "pii", "gdpr", "anonymi*e", "sanitize" — AND must require the
    round-trip to operate on an existing persisted file, not a live
    buffer before first write.

edge_case_strategies:
  - ast-read-filter-write-roundtrip
  - shell-sed-in-place
  - rw-mode-open-on-audit-path
  - timestamp-forgery-detection
  - redaction-context-exclusion

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - audit_path_match
    - tampering_operation
    - no_append_only_enforcement
  location_kinds:
    - source

obsolescence:
  retire_when: >
    MCP servers emit audit events exclusively to a write-once store
    (append-only WAL, immutable cloud audit log service, or blockchain-
    backed event stream) declared in the server manifest, AND the MCP
    specification requires that tools/list responses identify the audit
    sink. At that point static rewriting of a log file is structurally
    impossible — the rule has nothing to detect.

mutations_survived:
  - split-string-literal
  - unicode-homoglyph-identifier
  - base64-wrap-payload
mutations_acknowledged_blind: []
---

# K3 — Audit Log Tampering

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** MCP server source code, build scripts (Dockerfile RUN
lines), and post-install hooks that touch files whose path contains a
log / audit / journal substring.

## Distinct from K2 (audit-log destruction)

K2 detects *deletion* — `rm`, `unlink`, `truncate` against an audit
file. K3 detects the harder variant: the log still exists but its
contents have been rewritten. K3 is harder to detect externally because
the file size, filename, and structural shape all look normal.

## What an auditor accepts as evidence

An ISO 27001 A.8.15 auditor will accept:

1. **Source proof** — a `source`-kind Location at a `readFileSync` /
   `fs.open` / `sed -i` call whose target argument text contains a log
   / audit / journal substring.

2. **Propagation proof** — for the read-filter-write variant, a
   sequence of statements in the same function scope that transforms
   the read content. For the `sed -i` variant, the single command line
   is the propagation.

3. **Sink proof** — a `writeFileSync` / `fs.write` / shell redirect
   call whose target path matches the earlier read. For the
   `r+`-mode open variant, the open call itself is both source and
   sink (the file is open for in-place mutation).

4. **Mitigation check** — the rule reports whether any append-only
   enforcement is visible in the same file (e.g. an explicit `"a"` /
   `"a+"` flag, or `O_APPEND`). Absence is the finding; presence
   reduces confidence because a correctly-appending code path elsewhere
   in the file may still be in use.

5. **Impact** — tied to EU AI Act Art. 12: an AI system that cannot
   reconstruct its own history fails the Article's record-keeping
   obligation. Real-world incident response cannot attribute
   authentication failures or tool-call outcomes; regulators treat
   this as strictly worse than log deletion because it creates a
   false record.

## Why confidence is capped at 0.85

PII redaction pipelines do round-trip the log content, and a static
rule cannot always prove the difference between "removing the
attacker's row" and "removing a user's email address". The 0.85 cap
preserves room for the redaction-context-exclusion edge case.
