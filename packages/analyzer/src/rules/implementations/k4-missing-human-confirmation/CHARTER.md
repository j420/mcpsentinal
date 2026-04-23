---
rule_id: K4
interface_version: v2
severity: high

threat_refs:
  - kind: spec
    id: EU-AI-Act-Art-14
    url: https://eur-lex.europa.eu/eli/reg/2024/1689/oj
    summary: >
      EU AI Act Article 14 requires that high-risk AI systems be designed and
      developed in such a way that they can be effectively overseen by natural
      persons during the period in which they are in use. An MCP tool that
      performs a destructive operation without a required confirmation
      parameter or an equivalent server-side gate cannot be effectively
      overseen: the operator sees the action only after it has occurred.
      Art. 14(4)(d) names exactly the oversight mechanism this rule enforces —
      the human oversight measure must allow the person overseeing the system
      to intervene or interrupt the system through a "stop" function.
  - kind: spec
    id: ISO-42001-A.9.2
    url: https://www.iso.org/standard/81230.html
    summary: >
      ISO/IEC 42001:2023 Annex A Control 9.2 — Human oversight. Requires
      mechanisms for humans to control and intervene in AI system behaviour.
      Destructive operations invocable without a confirmation parameter
      defeat the control by schema, not by policy — i.e. the control is
      unenforceable regardless of runtime behaviour.
  - kind: spec
    id: ISO-42001-A.9.1
    url: https://www.iso.org/standard/81230.html
    summary: >
      ISO/IEC 42001:2023 Annex A Control 9.1 — Acceptable use. Expands on
      A.9.2 by requiring that human-in-the-loop controls cover every
      high-consequence operation. "High-consequence" in the MCP context
      includes any tool whose semantic class is irrevocable (drop, truncate,
      destroy, purge, wipe) or privilege-altering (revoke, ban, disable).
  - kind: spec
    id: NIST-AI-RMF-GOVERN-1.7
    url: https://www.nist.gov/itl/ai-risk-management-framework
    summary: >
      NIST AI RMF GOVERN 1.7 — organisations establish mechanisms for the
      decommission of AI systems and the override of their decisions. A tool
      whose destructive action has no confirmation gate has, by construction,
      no override mechanism at the invocation boundary.
  - kind: spec
    id: OWASP-ASI09
    url: https://owasp.org/www-project-agentic-security-initiative/
    summary: >
      OWASP Agentic Security Initiative (2025) Top 10, ASI09 — Human-Agent
      Trust Exploitation. Absent confirmation gates on destructive tools are
      the archetype: the AI gets to execute a destructive path using the
      operator's implicit trust rather than explicit intent.
  - kind: spec
    id: CoSAI-MCP-T2
    url: https://www.coalitionforsecureai.org/publications/mcp-threat-taxonomy
    summary: >
      Coalition for Secure AI MCP threat taxonomy (Jan 2026), threat category
      T2 — Missing Access Control, subtype "insecure human-in-the-loop".
      Specifies that destructive MCP tools must require a consent step at
      the schema layer, not merely via in-client conventions.
  - kind: paper
    id: Invariant-Labs-2025-consent-fatigue
    url: https://invariantlabs.ai/research/consent-fatigue
    summary: >
      Invariant Labs (2025) — "Consent fatigue in MCP tool approval". Quantifies
      an 84.2% success rate for tool poisoning when destructive tools are
      intermixed with benign ones in an auto-approve-enabled client; the
      absence of a schema-level confirmation parameter is the structural
      enabler of that attack. Documents the exact finding shape this rule
      produces.

lethal_edge_cases:
  - >
    Compound token with a soft marker — tools named `soft_delete_user`,
    `archive_record`, or `trash_file` describe reversible operations. The
    rule must still fire (Art.14 requires oversight of ALL consequential
    operations) but confidence must be calibrated downward via the
    soft_marker_reduces_severity factor. A naive substring detector that
    fires on "delete" alone would over-state the severity.
  - >
    Optional confirmation parameter — a tool exposes `confirm: boolean` in
    `properties` but omits it from `required`. The AI client is free to
    invoke the tool without setting confirm. Any detector that checks
    "does the schema mention confirm?" passes this case; the rule MUST
    additionally check the `required` list.
  - >
    MCP destructiveHint annotation present but schema ungated — the
    developer set `annotations.destructiveHint: true`. MCP-aware clients
    (Claude Desktop, Cursor) will prompt, but MCP-unaware clients (shell
    agents, custom harnesses) do not read annotations. The rule must not
    be silenced by the annotation alone; it records the annotation as a
    partial mitigation and keeps firing with reduced confidence.
  - >
    Camouflaged test file — production logic wrapped in a top-level
    `describe(...)` / `it(...)` call so a naive filename-based test
    detector skips it. The rule must use structural test-file detection:
    top-level runner call AND (runner-module import OR ≥2 runner calls OR
    nested runner calls). Acknowledged false-negative window: an attacker
    adding a dummy runner import plus a single `describe(...)` wrapper
    would still fool this — the charter records this as out-of-scope for
    Phase 1 and defers to supply-chain rules that would flag the unused
    dependency.
  - >
    Receiver-method alias for confirmation — the handler uses
    `await window.confirm(...)` or `await inquirer.prompt(...)` rather
    than a bare `confirm(...)` call. A guard walker that only matches
    bare identifiers misses this. The rule walks property-access
    expressions and checks receiver/method pairs against a curated
    whitelist (window.confirm, inquirer.prompt, rl.question).
  - >
    Forward-flow guard without enclosing IfStatement — the pattern
    `const ok = await confirm("…"); if (!ok) return; deleteAll();` places
    the destructive call OUTSIDE the IfStatement's thenStatement. A pure
    ancestor walk from the call site misses the guard. The rule handles
    this by inspecting preceding sibling statements in the enclosing
    Block/SourceFile for direct confirmation calls (await confirm, await
    approve). Acknowledged limitation: the rule does not implement full
    forward dominator analysis; a guard separated from the destructive
    call by unrelated statements is NOT recognised.
  - >
    String-indexed dynamic dispatch — `const fn = map["delete"]; fn(...)`.
    The call's expression is an ElementAccessExpression with a dynamic
    key; the symbol cannot be statically extracted. The rule deliberately
    returns null from `extractCallSymbol` in this case and acknowledges
    the false-negative in the charter. Detection of this pattern is a
    cross-cutting concern that belongs in a taint-style follow-up.

edge_case_strategies:
  - morpheme-tokenisation          # snake/camel/kebab/digit split before verb lookup
  - required-param-check           # confirmation only counts when in schema.required
  - annotation-partial-mitigation  # destructiveHint recorded but not silencing
  - structural-test-file-detection # runner import + top-level runner call + nested
  - ancestor-guard-walk            # IfStatement dominance from call to enclosing function
  - preceding-sibling-confirmation # forward-flow guard detection for the Block pattern
  - receiver-method-guard          # property-access confirmation calls (window.confirm etc.)

evidence_contract:
  minimum_chain:
    source: true        # the classified tool OR the destructive call site
    propagation: false  # present for schema findings (schema-unconstrained); optional for code
    sink: true          # the privilege-grant moment
    mitigation: true    # MUST record present/absent for BOTH schema gate AND annotation
    impact: true        # must describe the concrete oversight-gap consequence
  required_factors:
    - destructive_verb_irrevocable | destructive_verb_destructive | destructive_verb_privilege
    - no_guard_in_ancestor_chain | bulk_operation_marker
  location_kinds:
    - tool              # kind:"tool" for schema-surface findings
    - schema            # kind:"schema" with RFC 6901 json_pointer for schema findings
    - source            # kind:"source" with file:line:col for code-surface findings

obsolescence:
  retire_when: >
    The MCP specification mandates that clients must refuse to execute any
    tool whose name tokenises to a destructive verb without first receiving
    a user-affirmative signal (spec-level confirmation handshake),
    independently of the tool's own schema — OR EU AI Act Art.14 is
    superseded by a control that accepts post-hoc log-only oversight, which
    is not a direction the regulatory trajectory is taking.

mutations_survived:
  - split-string-literal
  - unicode-homoglyph-identifier
  - base64-wrap-payload
mutations_acknowledged_blind: []
---

# K4 — Missing Human Confirmation for Destructive Operations

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** MCP servers exposing tools whose semantic class is
destructive, and the underlying TypeScript/JavaScript handlers those tools
dispatch to.

## What an auditor accepts as evidence

An EU AI Act Art. 14 auditor will not accept a rule that says "this tool
has 'delete' in its name, so it is a compliance gap". They will accept a
rule that says:

1. **Classification proof** — the finding carries the tokenisation of the
   tool name (or the called symbol), the destructive verb it matched,
   the verb's class (irrevocable / destructive / privilege), and any
   bulk / soft markers. The classification is reproducible: an auditor
   re-tokenising the same symbol reaches the same answer.

2. **Gate proof (schema)** — the finding states, with a `schema` Location
   carrying an RFC 6901 JSON pointer, which parameters exist and which
   ones are in `required`. The absence of a `required` confirmation
   parameter is the compliance gap; the presence of an optional one is
   NOT a mitigation.

3. **Gate proof (code)** — for a code-surface finding, the ancestor walk
   from the destructive call to its enclosing function is recorded, with
   an explicit enumeration of what was checked (IfStatement conditions
   referencing guard identifiers; calls to confirm/prompt/approve/ask/
   verify/acknowledge/requireConfirmation/requestApproval/elicit; receiver.
   method calls against a whitelist). The enumeration is the proof —
   regulators can re-run the walk.

4. **Annotation check** — `annotations.destructiveHint` is recorded
   present/absent. Presence is a partial mitigation (MCP-aware clients
   prompt; MCP-unaware clients do not), reducing confidence; it does not
   silence the finding.

5. **Impact statement** — concrete: what an attacker or a confused AI
   agent gains by invoking the tool on the normal control-flow path;
   whether the operation is bulk (plural blast radius) or single.

## What the rule does NOT claim

- It does not claim that every reversible operation needs a confirmation
  gate. Soft-delete / archive / trash operations receive the finding
  (Art. 14 still applies) but at reduced confidence via the
  `soft_marker_reduces_severity` factor.

- It does not claim that `destructiveHint: true` plus any optional
  confirmation parameter is sufficient. Regulators require a gate at
  the schema layer OR a gate at the code-path layer — one of the two,
  not hints alone.

- It does not implement forward dominator analysis. A guard that is
  separated from the destructive call by intermediate statements (where
  the intermediate statements do not contain the destructive call itself)
  is NOT recognised. The sixth lethal edge case above records this.

## Why confidence is capped at 0.92

The static analyzer cannot see:

- runtime MCP-client consent dialogs (Claude Desktop, Cursor inject one
  based on `destructiveHint` — visible behaviour, not source-visible);
- middleware-enforced confirmation (a server-side Express middleware
  that halts every destructive tool-call on a queue until an admin
  approves — observable in `app.use(approvalQueue)` but not guaranteed
  to be wired to THIS tool);
- elicitation flows (MCP 2025-06-18 elicitation capability — server asks
  the user mid-call).

A maximum-confidence claim from static analysis would overstate what is
provable; the 0.92 cap preserves room for those externalities while
still signalling high confidence (the chain itself is dense with
evidence).

## Relationship to K5

K5 — Auto-Approve / Bypass Confirmation Pattern — is the INVERSE test.
K5 fires when a server has a confirmation mechanism but documents
bypassing it (`skip_confirmation`, `auto_approve`); K4 fires when the
mechanism is simply absent. A well-configured server fails neither.
A misconfigured server can fail both; a compliance scan that reports
both on the same tool is NOT a duplicate — the two findings describe
different control failures in the oversight chain.
