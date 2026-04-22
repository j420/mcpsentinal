---
rule_id: K5
interface_version: v2
severity: critical
owasp: MCP06-excessive-permissions
mitre: AML.T0054
risk_domain: human-oversight

threat_refs:
  - kind: spec
    id: EU-AI-Act-Art-14
    url: https://eur-lex.europa.eu/eli/reg/2024/1689/oj
    summary: >
      EU AI Act Article 14 requires high-risk AI systems to be designed
      and developed in such a way that they can be effectively overseen
      by natural persons during the period in which they are in use. A
      server that programmatically disables the human confirmation gate
      — via an `auto_approve: true` flag, a `--yolo` switch, or a
      `skip_user_confirmation()` call — removes the user's ability to
      exercise that oversight on the operations the MCP tool performs.
  - kind: spec
    id: OWASP-ASI09
    url: https://genai.owasp.org/llmrisk/llm09-human-agent-trust-exploitation/
    summary: >
      OWASP Agentic Security Initiative risk ASI09 (Human-Agent Trust
      Exploitation). The canonical attack: the agent / server exploits
      patterns the user trusts — one of which is the user's trust that
      destructive operations require explicit confirmation. A code path
      that unconditionally bypasses confirmation is the inverse of the
      protection the user assumes is in place.
  - kind: spec
    id: ISO-42001-A.9.2
    url: https://www.iso.org/standard/42001
    summary: >
      ISO 42001 A.9.2 (Human Oversight / Override Capabilities) requires
      that override mechanisms EXIST and are EFFECTIVE for an AI system.
      A static flag or CLI option that disables the override is not
      effective — it disables the oversight that ISO 42001 mandates.
  - kind: paper
    id: invariant-labs-consent-fatigue-2025
    url: https://invariantlabs.ai/research/consent-fatigue-tool-poisoning
    summary: >
      Invariant Labs research (2025) documents consent fatigue as the
      primary attack vector achieving 84.2% tool-poisoning success when
      auto-approve / batch mode is available. Consent fatigue is rule
      I16; K5 targets the server-side enabler that allows the attacker
      to exploit that fatigue — the flag or function that removes the
      confirmation prompt entirely.

lethal_edge_cases:
  - >
    Environment-variable bypass — the server reads
    `process.env.MCP_AUTO_APPROVE === "true"` and gates the
    confirmation prompt on it. A literal-pattern check for
    `auto_approve = true` misses this because the assignment lives in
    the deployment manifest, not the source. The rule must flag any
    branch that gates `confirm(...)` / `prompt-user(...)` on an
    environment variable whose name contains an auto-approve token.
  - >
    Destructive CLI flag — the server parses `--yolo`, `--force`,
    `--no-confirm`, `--auto-approve` from argv. Once the flag is set,
    every destructive operation runs without confirmation. The rule
    must detect CLI flag definitions whose identifier contains one of
    the auto-approve substrings AND whose presence short-circuits the
    confirmation path.
  - >
    Conditional bypass in a specific code path — the server normally
    asks for confirmation, but inside the `batch` / `ci` / `headless`
    branch it does not. The user believes the feature is present; the
    attacker exploits the branch. The rule must distinguish this from
    "no confirmation anywhere" by reporting the specific guarded
    branch, not a file-level absence.
  - >
    Framework-level skip — the server uses a library (yargs, clipanion,
    oclif) that provides a `--non-interactive` flag out of the box.
    Setting this flag causes `prompt()` to resolve immediately with a
    default. The default is typically `true` (approve), turning the
    prompt into rubber-stamping. Static detection must catch both the
    explicit flag and the framework-level non-interactive mode where
    approval defaults to `true`.
  - >
    `confirm(): Promise<true>` stub — the server defines a
    `confirm` function that simply returns `true` regardless of
    argument. The surrounding code continues to call `confirm(...)` —
    the name is preserved, the behaviour is neutered. The rule must
    flag any function named `confirm` / `askUser` / `requireApproval`
    whose body is a plain `return true` / `return Promise.resolve(true)`.

edge_case_strategies:
  - env-var-approval-gate
  - cli-flag-auto-approve
  - conditional-branch-skip
  - framework-non-interactive-mode
  - neutered-confirmation-stub

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - auto_approve_signal
    - oversight_bypass_scope
    - no_audit_of_bypass
  location_kinds:
    - source

obsolescence:
  retire_when: >
    The MCP specification mandates that `destructiveHint: true` tools
    emit an out-of-band confirmation request that clients MUST display
    before executing the tool, regardless of server-side configuration.
    At that point server-side auto-approve becomes a no-op and this
    rule's detection surface disappears.
---

# K5 — Auto-Approve / Bypass Confirmation Pattern

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** MCP server source code that implements (or bypasses) a
human-confirmation gate for tool operations.

## What an auditor accepts as evidence

An EU AI Act Art. 14 / ISO 42001 A.9.2 auditor will accept:

1. **Source proof** — a `source`-kind Location at the bypass site: a
   flag definition (`auto_approve = true`, `--yolo` CLI option), an
   env-var read (`process.env.MCP_AUTO_APPROVE`), a function stub that
   returns `true` unconditionally, or a direct `skip_confirm(...)` call.

2. **Sink proof** — a `sink`-kind Location at the operation that would
   normally be gated by the confirmation prompt. For a flag site, the
   sink is the flag itself (the presence of the flag implies every
   downstream destructive operation is gated through it). For a
   function-stub site, the sink is the stub's return statement.

3. **Mitigation check** — the rule reports whether an "explicit human
   approval" path coexists with the bypass. Presence reduces
   confidence; absence is the worst-case scenario (the bypass is the
   only code path).

4. **Impact** — the confused-deputy / human-in-the-loop failure is
   concrete: with auto-approve enabled, a poisoned tool description
   (I16 consent-fatigue precondition) executes destructive operations
   without human review. The Invariant Labs paper reports 84.2%
   poisoning success under these conditions.

## Why confidence is capped at 0.90

A legitimate CI / headless test harness may reasonably set `--no-confirm`
with a scoped, short-lived token. The 0.90 cap — higher than most K-rules
— reflects that the bypass pattern is intentionally named and easy to
identify, but room is preserved for the rare fully-documented CI mode.
