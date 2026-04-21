---
rule_id: A7
interface_version: v2
name: Zero-Width and Invisible Character Injection
severity: critical
owasp: MCP01-prompt-injection
mitre: AML.T0054
analysis_technique: unicode
confidence_cap: 0.95
threat_refs:
  - id: CVE-2021-42574
    kind: cve
    url: https://trojansource.codes/
    summary: |
      "Trojan Source" — Bidirectional Unicode overrides in source code cause
      logical and rendered character orders to diverge. Reviewers see a
      different string than the compiler/interpreter reads. The same
      divergence attacks MCP tool descriptions: the reviewer sees benign
      prose; the LLM reads an attacker-controlled directive.
  - id: AML.T0054
    kind: mitre-atlas
    url: https://atlas.mitre.org/techniques/AML.T0054
    summary: |
      LLM Prompt Injection. Invisible Unicode codepoints in tool metadata
      embed instructions that are invisible to human reviewers but fully
      legible to language models, delivering an injection payload via a
      surface that passes casual inspection.
  - id: UNICODE-TR36
    kind: standard
    url: https://www.unicode.org/reports/tr36/
    summary: |
      Unicode Security Considerations — catalogues invisible characters,
      bidi controls, tag characters, and their misuse for identifier
      spoofing and content confusion.
  - id: UNICODE-TR39
    kind: standard
    url: https://www.unicode.org/reports/tr39/
    summary: |
      Unicode Security Mechanisms — specifies restrictions (Moderately
      Restrictive, Single-Script, ASCII-Only) that would structurally
      prevent invisible-codepoint injection if adopted by MCP clients.
lethal_edge_cases:
  - |
    Legitimate ZWJ (U+200D) inside emoji sequences (flag, family, skin-tone,
    profession combinations). A ZWJ flanked on BOTH sides by emoji
    codepoints is Unicode-blessed ligature behaviour and MUST NOT be
    reported. Suppression is applied in gather.ts.
  - |
    Legitimate variation selectors (U+FE0E text-style, U+FE0F emoji-style)
    immediately after an emoji codepoint in a tool DESCRIPTION. These are
    the canonical presentation selectors and must be suppressed. In tool
    NAMES, variation selectors are ALWAYS reported — identifiers must not
    carry them.
  - |
    BOM (U+FEFF) at position 0 of a field — legitimate UTF-16 byte-order
    mark. Anywhere else, BOM is an invisible insertion and is reported.
  - |
    Arabic and Devanagari scripts use ZWJ / ZWNJ legitimately for glyph
    shaping. We do NOT currently detect the surrounding script context for
    these codepoints — a tool whose name or description mixes Latin with
    Arabic/Devanagari and relies on U+200D for shaping may produce a false
    positive. This is acknowledged: MCP tool identifiers are conventionally
    ASCII, so the realistic exposure is negligible; descriptions intended
    for Arabic/Devanagari readers will show at most one finding per ZWJ
    cluster and a reviewer can dismiss it.
  - |
    A6 (homoglyphs) and A7 (invisible chars) can both fire on the same
    tool. This is intentional: they describe different attacks on
    overlapping surfaces. The deduplication contract lives at the scoring
    layer (F1 trifecta cap) and is NOT this rule's responsibility.
  - |
    Normalisation is NEVER applied before detection. NFKC would erase
    zero-width characters silently; that would make the rule blind. We
    operate on raw codepoints and retain the original byte offsets in
    every verification step.
edge_case_strategies:
  - |
    Codepoint catalogue is declared once in data/invisible-codepoints.ts
    as a Record keyed by arbitrary stable ids (e.g. "zwsp", "bom",
    "bidi_embedding"). The detection logic iterates `Object.keys` on this
    Record — no regex, no long string-array literals.
  - |
    Emoji ZWJ/VS suppression: gather.ts checks the previous and next
    codepoints when a ZWJ or variation-selector candidate is observed. The
    check uses the shared EMOJI_RANGES table and is applied ONLY to
    descriptions (identifiers are never granted the exception).
  - |
    Tag-character decoding: if a description contains three or more tag
    codepoints in the U+E0020–U+E007E subrange, the decoded ASCII string
    is surfaced in the finding as `hidden_tag_message`. The verification
    step shows the reviewer how to reproduce the decoding independently.
  - |
    Bidi gets its own dedicated finding (critical severity) separate from
    the aggregated description finding, because bidi is uniquely
    dangerous: it produces a divergence between rendered and logical text
    that ordinary stripping / hex-dumping does not surface. The finding
    cites CVE-2021-42574 directly.
evidence_contract:
  minimum_chain:
    source: true
    sink: true
    propagation: true
    mitigation: false
    impact: true
    verification_steps: 1
    threat_reference: true
obsolescence:
  retire_when: |
    MCP adopts a mandatory "ASCII-printable only" identifier policy AND
    reference clients strip invisible codepoints from all tool metadata at
    registration. At that point invisible-codepoint injection is
    structurally impossible against MCP, and this rule becomes redundant.
---

# A7 — Zero-Width and Invisible Character Injection

## Why this rule exists

An MCP tool's identity and semantic description reach the LLM as plain UTF-8
text. The LLM processes every codepoint, including those that render as
nothing in any GUI or terminal. Attackers exploit this asymmetry in three
canonical ways:

1. **Identifier smuggling** — a tool name with an embedded zero-width space
   collides with a legitimate tool name under naïve string equality while
   remaining a distinct object in any codepoint-aware registry. The AI
   client routes by string, the human reviewer routes by glyph, and the
   two disagree silently.

2. **Steganographic prompt injection** — tag characters (U+E0020–U+E007E)
   map 1:1 to ASCII printable characters. An attacker hides a full
   instruction sequence inside invisible tag codepoints appended to an
   otherwise benign description. The instructions are invisible to every
   reviewer but read normally by the LLM.

3. **Bidi deception (Trojan Source style)** — U+202E (RLO) reverses the
   rendered order of the following text. A reviewer sees "safe tool for
   file reads" while the LLM reads a reversed directive.

## What the detection does

A single codepoint-by-codepoint pass over every tool NAME, DESCRIPTION,
and PARAMETER DESCRIPTION. For each codepoint we look up its containing
range in `data/invisible-codepoints.ts`; if a range is matched, we record
an `InvisibleHit` unless one of the suppression rules applies (see
`edge_case_strategies` above).

Four independent finding types are emitted:

- **Name finding** (critical) — any invisible codepoint in a tool name.
- **Description finding** (critical or high) — ≥1 invisible codepoint in a
  description. Severity escalates to *critical* when tag codepoints decode
  to an ASCII message ≥3 characters long.
- **Bidi finding** (critical) — dedicated finding citing CVE-2021-42574
  when U+202A–U+202E or U+2066–U+2069 appear in a description.
- **Parameter finding** (high) — invisible codepoints in a parameter
  description. Overlaps with B5; that overlap is intentional.

## Evidence contract

Every finding carries:

- A **source** link pinned to `tool:<name>:<field>` (structured location).
- A **propagation** link describing how the invisible content reaches the
  LLM's context window.
- A **sink** link describing the concrete downstream effect
  (`privilege-grant` for identifiers, `code-evaluation` for descriptions).
- An **impact** link with `exploitability: trivial` when a tag-decoded
  message is present; `moderate` otherwise.
- A **threat reference** — AML.T0054 by default, CVE-2021-42574 for bidi
  findings.
- ≥1 **verification step** showing the reviewer how to hex-dump and
  reproduce the observation. Descriptions with tag codepoints include a
  second step instructing the reviewer to decode the hidden ASCII payload
  manually.

## Confidence

Capped at **0.95**. Codepoint detection is exact, but residual intent
ambiguity remains (e.g. a single stray soft hyphen that may be a typo
rather than an attack). Findings with tag-decoded payloads carry the
additional factor `hidden_tag_message_decoded (+0.25)` and typically
compute to very high confidence before the cap.

## Not covered here (on purpose)

- Homoglyphs in visible scripts: **A6 (Unicode Homoglyph Attack)**.
- Encoded (base64 / hex / URL) instructions in descriptions:
  **A9 (Encoded Instructions in Description)**.
- Length-based attention-window attacks: **G4 (Context Window Saturation)**.
