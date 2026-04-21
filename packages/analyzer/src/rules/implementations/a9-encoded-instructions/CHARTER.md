---
rule_id: A9
interface_version: v2
severity: critical

threat_refs:
  - kind: spec
    id: MITRE-AML.T0054
    url: https://atlas.mitre.org/techniques/AML.T0054
    summary: >
      MITRE ATLAS AML.T0054 — LLM Prompt Injection. Encoded instructions in a
      tool description are a direct-injection delivery vector: the LLM reads
      the description, decodes the payload (base64 / URL-encoded / \u escapes
      / HTML entities) from its built-in knowledge of those encodings, and
      follows the decoded directive with the trust ordinarily extended to
      tool metadata.
  - kind: spec
    id: MITRE-AML.T0054.002
    url: https://atlas.mitre.org/techniques/AML.T0054.002
    summary: >
      MITRE ATLAS AML.T0054.002 — Direct Prompt Injection sub-technique.
      Covers the specific case where the injection payload is delivered in
      surface content under the attacker's control that the target model
      ingests verbatim. Encoding the payload obscures it from human PR /
      registry review while preserving LLM-readability.
  - kind: paper
    id: INVARIANT-LABS-MCP-INDIRECT-2025
    url: https://invariantlabs.ai/research/mcp-indirect-injection
    summary: >
      Invariant Labs (2025) — "MCP Indirect Injection Research". Demonstrates
      real-world tool-poisoning campaigns in which the injection payload was
      base64-encoded inside the tool description. Documents the 84.2% success
      rate for auto-approve client configurations and names encoding as the
      primary reviewer-evasion technique.
  - kind: spec
    id: OWASP-MCP01
    url: https://owasp.org/www-project-mcp-top-10/
    summary: >
      OWASP MCP Top 10 — MCP01 Prompt Injection. Lists encoded payloads in
      tool metadata as a canonical instance of the prompt-injection category.
      The OWASP guidance specifically calls out the need for deterministic
      structural detection (entropy + alphabet scanning) rather than
      regex blocklists, which is the approach A9 implements.

lethal_edge_cases:
  - >
    JWT tokens in tool descriptions as illustrative examples — eyJ... strings
    are genuine base64url. A 32+ character JWT WILL fire. The rule records
    `inspect-description` verification steps asking reviewers to confirm
    a surrounding "example JWT" disclaimer.
  - >
    Unicode escapes in non-English descriptions — Japanese / CJK text rendered
    with literal \uNNNN escapes is rare but possible. The
    `non_latin_surrounding_context` factor subtracts 0.08 when the ±100-char
    window around the detected run is <50% Latin-script.
  - >
    Mixed-encoding layering — two or more encoding categories co-occurring
    on the same surface is a deliberate evasion technique (layering to
    defeat single-decoder scanners). A9 promotes this to `mixed-encoding`
    critical severity rather than reporting each category independently.
  - >
    Mis-padded base64 blocks (length % 4 ≠ 0) — deliberate or accidental,
    still decodes in many LLM implementations. A9 does NOT enforce padding
    strictness.
  - >
    base32 / base85 / ascii85 alphabets — explicitly out of scope. Their
    alphabets differ from base64 and would require separate scanners. The
    v1 A9 rule sometimes flagged these via Shannon entropy alone; v2
    trades that fuzzy coverage for deterministic, reviewer-reproducible
    findings. Charter records this as an acknowledged coverage gap.

edge_case_strategies:
  - structural-alphabet-scanner         # character-level walk over every surface using Record<char, true> lookups
  - shannon-entropy-threshold           # entropy guard on base64 runs separates real base64 from dense English
  - post-decode-keyword-match           # once a block decodes, look for LLM control tokens + injection keywords
  - mixed-encoding-layering-detection   # per-surface category set; ≥2 categories → critical
  - non-latin-context-downgrade         # confidence factor when ±100 chars of surroundings are <50% Latin

evidence_contract:
  minimum_chain:
    source: true          # the encoded run at its offset within the surface
    propagation: false    # optional — included when the decoder resolves the payload
    sink: true            # the LLM ingestion point (tool-description processing)
    mitigation: false     # no structural mitigation surface at static analysis time
    impact: true          # concrete injection scenario with decoded payload excerpt
  required_factors:
    - structural_encoding_run
    - llm_control_token_after_decode | multiple_injection_keywords_after_decode | single_injection_keyword_after_decode
  location_kinds:
    - tool                # kind:"tool" for tool-name / tool-description hits
    - parameter           # kind:"parameter" for input-schema parameter description hits
    - initialize          # kind:"initialize" for server_instructions / server_version hits

obsolescence:
  retire_when: >
    MCP clients mandate a pre-ingest decoder-aware filter that strips or
    neutralises ALL encoded-payload candidates (base64/url/hex/html) from
    every tool-metadata surface before the LLM sees it — OR the spec adds
    a required `content_encoding` declaration per metadata field that
    servers must opt into explicitly, making an undeclared encoding a
    protocol violation rather than a detection problem. Neither direction
    is current as of 2026-04.
---

# A9 — Encoded or Obfuscated Instructions in Tool Description

## Threat Model

An MCP server publisher embeds a prompt-injection payload inside one of the
tool-metadata surfaces the MCP client passes to the LLM. The payload is
encoded — base64, URL-encoding, JavaScript `\xNN` or `\uNNNN` escapes, or
HTML numeric entities — so human reviewers (GitHub PR diff, npm package page,
registry listing) see an opaque run rather than the instruction. The LLM
receives the same bytes verbatim and can decode them using in-built knowledge
of those encoding schemes. The decoded instruction then rides on the implicit
trust AI clients extend to tool descriptions and the spec-sanctioned
`initialize` `instructions` field.

## Detection Surfaces

| Surface                                                | Why it matters                                                           |
|--------------------------------------------------------|--------------------------------------------------------------------------|
| `tool.description`                                     | Primary surface — most common in reported attacks (Invariant Labs 2025) |
| `tool.name`                                            | Rare but seen; names pass through identical trust path                   |
| `input_schema.properties[*].description`               | Secondary injection surface (overlap with B5 — A9 still valid)           |
| `initialize_metadata.server_instructions`              | Processed before any tool description (overlap with H2 — A9 still valid) |
| `initialize_metadata.server_version`                   | Tiny field but still model-visible; covered for defence in depth         |

## Detection Strategy

Four deterministic structural scanners, all regex-free and character-level:

1. **base64-block** — ≥32 contiguous base64-alphabet chars (A–Z a–z 0–9 + / - _)
   with optional `=` padding, Shannon entropy ≥ 4.5 bits/char, and mixed-case
   or digit variety. Tries Buffer-based decode; records decoded preview.
2. **url-encoded-block** — ≥6 contiguous `%XX` triplets (enough to spell a
   short injection verb such as "ignore" / "system" / "reveal", while still
   statistically unlikely in natural prose). Decodes via `decodeURIComponent`.
3. **hex-escape-block** — ≥8 consecutive `\xNN` or ≥6 consecutive `\uNNNN`
   escapes. Manual hex decode.
4. **html-entity-block** — ≥10 consecutive `&…;` entity references.
   Numeric entities decoded manually.

Any surface where **≥2 categories co-occur** is promoted to `mixed-encoding`
and emitted at **critical** severity (layering is a deliberate evasion).

## Confidence Factors

| Factor                                   | Adjustment | Rationale                                                                                          |
|------------------------------------------|------------|----------------------------------------------------------------------------------------------------|
| `structural_encoding_run`                | +0.08      | Anchor: the structural match itself is high-signal                                                  |
| `high_entropy` (≥5.5 bits/char)          | +0.05      | Real base64 sits at 5.7–6.0; English is 3.0–4.5                                                     |
| `low_entropy_encoded_shape` (<4.0)       | -0.02      | Structural match but low entropy — possibly coincidental                                            |
| `llm_control_token_after_decode`         | +0.18      | Deterministic proof of injection intent (`<|im_start|>`, `[INST]`, role prefixes)                   |
| `multiple_injection_keywords_after_decode` | +0.10    | ≥2 keywords in decoded payload (ignore/override/system/credential/etc.)                             |
| `single_injection_keyword_after_decode`  | +0.05      | One keyword — supportive, not conclusive                                                            |
| `mixed_encoding_layering`                | +0.12      | ≥2 encoding categories on same surface                                                              |
| `non_latin_surrounding_context`          | -0.08      | <50% Latin-script surroundings — encoded runs in non-Latin descriptions are often literal data      |
| `decoder_failed`                         | -0.05      | Structural shape matched but canonical decoder refused — double-encoded or custom alphabet          |
| `sanitizer-function absent` (auto)       | +0.10      | No encoding filter applied in MCP client path                                                        |
| `entropy_static_analysis_cap`            | 0.00       | Post-hoc: confidence clamped to 0.90 (no rule is over-confident in static encoding detection)       |

## Confidence Cap

0.90. Static entropy analysis can false-positive on legitimate compressed or
encoded binary data embedded in descriptions (RFC examples, tutorial payloads,
JWT illustrative strings). The cap preserves reviewer headroom and acknowledges
that this rule can never reach the 0.99 ceiling reserved for taint-path proofs.

## Edge Cases (Honest Coverage Contract)

- **JWT tokens in tool descriptions as illustrative examples.** `eyJ…` base64url
  strings are genuine base64. The rule **will** fire on a ≥32-char JWT in a
  description. The `inspect-description` verification step instructs reviewers
  to check for an explicit "example JWT" disclaimer in the surrounding context
  and downgrade if present.
- **Unicode escapes in non-English descriptions.** A Japanese description
  rendered with literal `\uNNNN` escapes is rare but possible. The
  `non_latin_surrounding_context` factor subtracts 0.08 when the ±100-char
  window is <50% Latin.
- **Mis-padded base64.** Base64 blocks one character shy of `length % 4 === 0`
  are still matched; we do not enforce padding strictness, matching how real
  encoders sometimes omit padding.
- **base32 / base85 / ascii85.** **NOT COVERED.** The alphabets differ from
  base64 and would require their own scanner. The entropy-based A9 v1 rule
  sometimes flagged these via Shannon entropy alone; v2 intentionally trades
  that fuzzy coverage for deterministic, reviewer-reproducible findings.
- **XOR / steganographic payloads.** NOT COVERED by A9. The sliding-window
  entropy analysis in the companion description-analysis toolkit picks those
  up separately.

## Strategies (dual-persona authoring protocol)

- `structural_alphabet_scanner` — character-level walks over every surface
  using `Record<char, true>` lookups; no regex literals.
- `shannon_entropy_threshold` — entropy guard on base64 runs to separate real
  base64 from dense English.
- `post_decode_keyword_match` — once a block decodes, look for LLM control
  tokens and injection keywords. This is the single strongest signal.
- `mixed_encoding_layering_detection` — per-surface category set; two or more
  categories → critical.

## References (lethal edges the chain relies on)

- `tool_description_ingested_by_llm` — MCP clients include tool descriptions
  verbatim in the model prompt.
- `parameter_description_consulted_during_tool_call` — LLMs read parameter
  descriptions when filling arguments (B5 gateway).
- `initialize_instructions_processed_before_user_context` — the `instructions`
  field lands in the model context before any user turn (H2 gateway).
