---
rule_id: K2
interface_version: v2
severity: critical

threat_refs:
  - kind: spec
    id: ISO-27001-A.8.15
    url: https://www.iso.org/standard/82875.html
    summary: >
      ISO/IEC 27001:2022 Annex A Control 8.15 requires that event logs
      be produced, stored, PROTECTED, and analysed. Protection is
      explicitly defined to include protection against tampering and
      unauthorized deletion. Programmatic deletion / truncation of an
      audit log file from inside the MCP server's own code path is the
      exact failure mode the control is written to prevent. Canonical
      spec citation for K2.
  - kind: spec
    id: EU-AI-Act-Art-12
    url: https://eur-lex.europa.eu/eli/reg/2024/1689/oj
    summary: >
      EU AI Act Article 12 — Record-keeping. High-risk AI systems
      SHALL technically allow for the automatic recording of events
      over the duration of the system's lifetime. "Over the duration"
      means audit logs cannot be programmatically destroyed
      mid-lifetime; that breaks the Article 12 regime. MCP servers
      exposed to an agentic application are high-risk by virtue of
      their automation of consequential actions (Annex III cases).
  - kind: spec
    id: CoSAI-MCP-T12
    url: https://www.coalitionforsecureai.org/publications/mcp-threat-taxonomy
    summary: >
      Coalition for Secure AI — MCP Threat Taxonomy T12 "Insufficient
      Logging / Monitoring" explicitly includes log tampering and log
      destruction in its scope. K2 is the detection rule for the
      active-destruction sub-case; K1 covers the absent-logging case;
      K3 covers the read-filter-write tampering case.
  - kind: spec
    id: ISO-42001-A.8.1
    url: https://www.iso.org/standard/81230.html
    summary: >
      ISO/IEC 42001:2023 Annex A Control 8.1 — Transparency. An AI
      system whose operator can programmatically erase its audit trail
      provides no transparency to a downstream auditor. A deliberate
      audit-destruction call path violates the transparency obligation
      independently of whether it was ever triggered.
  - kind: paper
    id: MITRE-ATLAS-T0054
    url: https://atlas.mitre.org/techniques/AML.T0054
    summary: >
      MITRE ATLAS AML.T0054 — after gaining initial access through an
      MCP server, an adversary may erase the audit trail to prevent
      incident response. The presence of a programmatic deletion code
      path IS the primitive the technique uses.
  - kind: cve
    id: CVE-2024-52798
    url: https://nvd.nist.gov/vuln/detail/CVE-2024-52798
    summary: >
      path-to-regexp ReDoS — secondary K2 precedent. ReDoS-driven log
      flooding is one of the documented pretexts attackers use to
      motivate an admin to "clean up" logs by running the
      audit-destruction path; a server that ships that path is
      therefore a pre-positioned evidence-removal primitive.

lethal_edge_cases:
  - >
    Symlink unlink — the audit path is a symlink pointing at
    /dev/null; the attacker re-points the symlink and then calls
    fs.unlink(path). The rule fires on the unlink call with the
    original audit path — symlink resolution is an audit-time concern,
    not a detection-time one.
  - >
    Log rotation with retention=0 — fs.renameSync(log, archive)
    followed by fs.unlinkSync(archive) on the same control-flow path.
    A naive "rename = rotation, skip" rule would miss the immediate
    subsequent unlink. The rule treats rename+unlink in the same
    function scope with no archive step (no compress, no backup, no
    S3 upload) as destruction.
  - >
    Disable-logging wrapped in a dynamically-loaded module — the
    logger.silent = true assignment lives inside a file that is
    conditionally imported by a module factory gated on an env var.
    Static analysis still sees the assignment; detection does not
    depend on reachability because the presence of the toggle is a
    compliance violation independent of whether it fires at runtime.
  - >
    Truncate with 0 bytes — fs.truncateSync(auditPath, 0) empties the
    log without deleting the file. ISO 27001 A.8.15 considers this
    equivalent to deletion because the historical record is gone.
    The rule flags any truncate call regardless of its second
    argument.
  - >
    Path resolved through a typed config field —
    fs.unlink(config.auditPath) where config is read from a JSON
    file. The rule accepts `auditPath` / `logPath` / `journalPath`
    token-matches on the argument expression because verifying the
    config JSON is out of the source-file scope.

edge_case_strategies:
  - symlink-unlink-still-fires              # unlink on audit path regardless of symlink resolution
  - rename-then-unlink-without-archive      # rotation fake-out detection
  - logging-disable-structural              # presence of disable call is a violation, reachability optional
  - truncate-any-size-fires                 # truncate to any size empties the record
  - config-field-name-allowed               # config.auditPath / logPath resolve names accepted
  - silent-assignment                       # logger.silent = true / logger.level = "silent"
  - python-os-remove-audit-path             # os.remove / os.unlink on audit-named path

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - audit_path_identifier
    - unmitigated_destruction_reachability
    - rotation_or_archive_absent
  location_kinds:
    - source

obsolescence:
  retire_when: >
    MCP servers are required to emit audit records via a separate
    append-only transport (WORM storage, S3 Object Lock, a signed
    receipt chain) that is out of the server's own delete authority,
    AND ISO 27001 A.8.15 / EU AI Act Art. 12 agree that programmatic
    file-level deletion by the server itself is no longer within the
    compliance surface. At that point K2's file-level scan becomes
    irrelevant.
---

# K2 — Audit Trail Destruction

**Author:** Senior MCP Threat Researcher persona + Senior MCP Security
Engineer persona, dual authorship.
**Applies to:** MCP servers whose source code is scanned by Sentinel
(TypeScript / JavaScript / Python). The rule looks for three code
shapes, NOT a taint flow:

1. A file-deletion / truncation / rename-to-/dev/null call whose path
   argument contains an audit-identifier substring (`audit`, `log`,
   `journal`, `trace`, `record`, `.log`, `.audit`, a `config.*Path`
   field whose name contains those tokens).

2. A logger-disable primitive (`logging.disable(...)`,
   `logger.silent = true`, `logger.level = "silent"`,
   `audit.disable()`).

3. A file-write of an empty string / zero-length buffer to an audit
   path (equivalent to truncation).

## What an auditor accepts as evidence

An ISO 27001:2022 A.8.15 auditor will not accept "deletion call
detected". They require:

1. **Source** — a `source`-kind Location on the AST node where the
   audit-file path enters the destruction call. The Location points
   at the exact argument / RHS expression the destruction uses.

2. **Propagation** — optional. One link per hop when the path flows
   through a variable or config-field indirection.

3. **Sink** — a `source`-kind Location on the destruction call —
   `fs.unlinkSync` / `fs.rmSync` / `fs.truncateSync` / `os.remove` /
   `logging.disable` / `logger.silent = true`. `sink_type =
   "file-write"` for file destruction (truncation / empty-write /
   unlink), `sink_type = "config-modification"` for logging
   suppression.

4. **Mitigation** — present when the enclosing function ALSO contains
   a rotation / archive / backup / compress / gzip / S3-upload call
   in the same scope, which downgrades severity to `high` (not
   eliminated — a rotation that doesn't retain is still a compliance
   violation; the rule retains but de-escalates).

5. **Impact** — `config-poisoning` (scope `server-host`). The
   attacker gains the ability to erase evidence of malicious action;
   regulators block MCP server operation on the record-keeping
   dimension.

6. **Verification steps** — open the destruction call, confirm the
   audit identifier in the path, check for a rotation policy in the
   enclosing scope, confirm append-only storage is not configured.

## Why confidence is capped at 0.88

K2 detects a structural pattern. The 0.12 gap reserves room for:

- File-system paths that contain `log` as a substring for non-audit
  reasons (e.g. a build tool's `catalog.json` — unlikely but
  possible — the rule would still flag it at 0.88 for review).
- Rotation schemes implemented across multiple files the file-scope
  walker cannot see.
- Deployment-time immutable storage (S3 Object Lock, Azure Immutable
  Blob) that neutralises the destruction call at runtime without
  changing the source.
