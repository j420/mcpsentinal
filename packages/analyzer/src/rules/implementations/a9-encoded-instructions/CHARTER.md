---
rule_id: A9
name: Encoded or Obfuscated Instructions in Tool Description
severity: critical
owasp: MCP01-prompt-injection
mitre:
  - AML.T0054
  - AML.T0054.002
risk_domain: prompt-injection
technique: composite
requires:
  tools: true
  initialize_metadata: false
confidence_cap: 0.90
threat_refs:
  - id: MITRE-AML.T0054
    title: "MITRE ATLAS — LLM Prompt Injection"
    url: https://atlas.mitre.org/techniques/AML.T0054
  - id: MITRE-AML.T0054.002
    title: "MITRE ATLAS — Direct Prompt Injection"
    url: https://atlas.mitre.org/techniques/AML.T0054.002
  - id: INVARIANT-LABS-MCP-INDIRECT-2025
    title: "Invariant Labs — MCP Indirect Injection Research (2025)"
  - id: OWASP-MCP01
    title: "OWASP MCP Top 10 — MCP01 Prompt Injection"
lethal_edges:
  - tool_description_ingested_by_llm
  - parameter_description_consulted_during_tool_call
  - initialize_instructions_processed_before_user_context
strategies:
  - structural_alphabet_scanner
  - shannon_entropy_threshold
  - post_decode_keyword_match
  - mixed_encoding_layering_detection
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
