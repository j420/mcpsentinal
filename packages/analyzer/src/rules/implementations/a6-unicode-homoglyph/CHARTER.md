---
rule_id: A6
interface_version: v2
name: Unicode Homoglyph Attack
severity: critical
owasp: MCP02-tool-poisoning
mitre: AML.T0054
analysis_technique: unicode
confidence_cap: 0.95
threat_refs:
  - id: CWE-1007
    kind: cwe
    url: https://cwe.mitre.org/data/definitions/1007.html
    summary: |
      Insufficient Visual Distinction of Homoglyphs Before Rendering — the canonical
      weakness describing identifiers whose glyph sequence is identical to another
      identifier while the underlying codepoint sequence differs. The basis for all
      Unicode-based identity-impersonation attacks.
  - id: UNICODE-TR39
    kind: standard
    url: https://www.unicode.org/reports/tr39/
    summary: |
      Unicode Security Mechanisms — defines confusable-detection tables, mixed-script
      detection, and restriction-level policies (ASCII-only, Single-Script, Highly
      Restrictive). Our codepoint tables are derived from TR39 confusables.txt
      restricted to pairs that are visually indistinguishable in common fonts.
  - id: AML.T0054
    kind: mitre-atlas
    url: https://atlas.mitre.org/techniques/AML.T0054
    summary: |
      LLM Prompt Injection. Homoglyph-encoded tool names and descriptions are one
      vector for injection that bypasses lexical filters while remaining legible to
      the language model after internal normalisation.
lethal_edge_cases:
  - |
    A legitimate internationalised server whose tool names or descriptions mix
    Latin with Cyrillic/Greek for real localisation reasons (e.g. a Russian-
    language MCP server documenting tools in Russian). The rule ONLY flags
    Latin-dominant identifiers that also contain lookalike codepoints — a
    pure-Cyrillic tool name is not flagged. This keeps FPs off non-Latin
    ecosystems.
  - |
    Multilingual prose descriptions that happen to contain a small number of
    cross-script words (e.g. an English description that quotes a Greek letter
    in a physics formula). The description-level detector requires ≥3 confusable
    clusters AND Latin-dominance before it fires. Single Greek letters in Latin
    prose are IGNORED by design.
  - |
    Emoji and combining-mark sequences (e.g. flag emojis, country codes,
    skin-tone modifiers) contain codepoints outside the Basic/Extended Latin
    range but are NOT confusables for Latin letters. The rule's codepoint
    tables enumerate confusables by hex key — codepoints not present in the
    tables are never reported. Emoji codepoints are in blocks
    (U+1F000+, U+2600–U+27BF) that do not overlap any lookalike script range.
  - |
    NFKC / NFC normalisation would erase some attacks before detection. We
    deliberately operate on raw codepoints: the `gather` phase records each
    suspicious codepoint AT ITS ORIGINAL INDEX, so an auditor can confirm the
    observation byte-for-byte against the raw tool registration. Normalisation
    is only used for shadow-collision detection, where the collision is the
    finding.
  - |
    Variation selectors (U+FE00–U+FE0F) appearing legitimately after emoji are
    NOT a homoglyph concern — they belong to A7 (zero-width / invisible).
    A6 only looks at confusables in lookalike SCRIPT RANGES; variation
    selectors are not in any script range.
edge_case_strategies:
  - |
    Script-mixing policy: only emit findings when an identifier contains BOTH
    Basic/Extended Latin codepoints AND codepoints from a lookalike script
    (Cyrillic, Greek, Armenian, Georgian, Cherokee, Fullwidth-Latin,
    Mathematical-Alphanumeric). This prevents false positives on
    single-script identifiers.
  - |
    Description density threshold: tool descriptions must contain ≥3
    confusable hits before the description-level finding fires. Below that
    threshold we assume legitimate cross-script prose.
  - |
    Evidence integrity: every `HomoglyphHit` carries the original codepoint,
    its position (zero-based character index), the Latin letter it
    impersonates, and its script block. The verification step instructs the
    auditor to hex-dump the raw value and confirm the codepoint — the
    observation is reproducible without running our detector.
evidence_contract:
  minimum_chain:
    source: true
    sink: true
    propagation: true
    mitigation: false
    impact: true
    verification_steps: 2
    threat_reference: true
obsolescence:
  retire_when: |
    The MCP specification adopts a mandatory Single-Script + TR39
    Moderately-Restrictive tool-name policy AND reference MCP clients reject
    mixed-script identifiers at registration time. At that point homoglyph
    attacks are structurally impossible and this rule becomes redundant.

mutations_survived:
  - split-string-literal
  - unicode-homoglyph-identifier
  - base64-wrap-payload
  - reorder-object-properties
mutations_acknowledged_blind: []
---

# A6 — Unicode Homoglyph Attack

## Why this rule exists

The MCP tool-selection surface identifies tools by their registered NAME. An
AI client presented with a list of tools decides which one to invoke by
matching the user's intent against those names — if two names render
identically but differ at the codepoint level, the client cannot route
deterministically, and an attacker who registers a homoglyph tool will
capture invocations that the user meant for the legitimate tool.

The same weakness applies to tool descriptions: a prompt-injection payload
written with Cyrillic/Greek substitutions passes string-level filters while
being read as plain Latin by the LLM.

## What the detection does

A single pass over every tool name and description, codepoint by codepoint.
For each codepoint we ask:

1. Is this in **Basic Latin** or **Extended Latin**? (flag `has_latin`)
2. Is this in a **lookalike-script range** (Cyrillic, Greek, Armenian,
   Georgian, Cherokee, Fullwidth-Latin, Mathematical-Alphanumeric)? (flag
   `has_lookalike`)
3. Is this codepoint in the **TR39 confusable table** we ship under
   `data/homoglyph-codepoints.ts`? (record a `HomoglyphHit`)

An identifier is reported only when `has_latin && has_lookalike` and at least
one hit is present. This is the script-mixing policy described above; it
prevents false positives on purely non-Latin identifiers.

Shadow-tool collision is the highest-confidence finding: when two tools in
the same server have different raw names whose TR39-normalised forms are
identical, the AI client cannot distinguish them. The `normaliseConfusables`
helper is used exclusively for this collision check; it is never run on
the observation surface.

## Evidence contract

Every finding carries:

- A **source** link pinning the suspicious codepoints to the specific tool
  field (`tool:<name>:name` or `tool:<name>:description` or
  `tool:<a>:name vs tool:<b>:name`).
- A **propagation** link describing how the identifier reaches the
  AI client's tool-selection context.
- A **sink** link (`privilege-grant`) stating the downstream effect —
  invocation routed to an attacker-controlled tool.
- A **mitigation** link recording that no Unicode-script validation is in
  place at the MCP protocol level.
- An **impact** link describing the concrete attack scenario.
- A **threat reference** — at minimum CWE-1007 or MITRE ATLAS AML.T0054.
- ≥2 **verification steps** that instruct a reviewer how to hex-dump the raw
  value and reproduce the codepoint observation.

## Confidence

Confidence is capped at **0.95**. Codepoint detection is deterministic; the
cap reflects residual ambiguity in the script-mixing intent (legitimate
multilingual identifiers exist but are rare in an MCP context).

## Not covered here (on purpose)

- Zero-width / invisible / bidi / tag characters: those are
  **A7 (Zero-Width Character Injection)**. A6 only looks at confusable
  codepoints in visible script blocks.
- Encoded prompt payloads (base64, hex): those are
  **A9 (Encoded Instructions in Description)**.
- Typosquatting based on edit distance (read_fike vs read_file): that is
  **A4 (Cross-Server Tool Name Shadowing)** and **D3 (Typosquatting Risk)**.
