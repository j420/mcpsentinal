---
rule_id: M4
interface_version: "v2"
severity: high

threat_refs:
  - kind: spec
    id: OWASP-MCP02
    url: https://owasp.org/www-project-top-10-for-large-language-model-applications/
    summary: >
      Tool poisoning is OWASP MCP02. Tool squatting is a specific form:
      the attacker publishes a tool whose description falsely claims
      authority ("official version", "verified implementation"). LLMs
      weight authority claims heavily when ranking multiple tools with
      overlapping capabilities, so squatting displaces the legitimate
      tool in tool-selection.
  - kind: technique
    id: MITRE-ATLAS-AML.T0054
    url: https://atlas.mitre.org/techniques/AML.T0054
    summary: >
      Tool squatting is a prompt-injection variant: the injection is in
      the tool's own description rather than in input data, but the
      mechanism is the same — authority-claim language manipulates the
      model's tool-selection reasoning.
  - kind: spec
    id: CoSAI-MCP-T4
    url: https://www.coalitionforsecureai.org/publications/mcp-threat-taxonomy
    summary: >
      CoSAI MCP taxonomy T4 (tool integrity) explicitly names false
      authenticity claims in tool metadata as a trust-layer violation.
      The rule detects the metadata-level claim, not runtime behaviour.

lethal_edge_cases:
  - >
    Negation inversion — the description says "this is an unofficial
    community fork of the real server". A naive anchor-token match
    would fire on "official" (inside "unofficial") and on "the real";
    the rule must detect the "un-" prefix and drop the confidence,
    and must recognise the disclaimer ("community fork") without
    firing on the bare token "real".
  - >
    Vendor impersonation without a claim verb — the description is
    "Anthropic MCP server for filesystem access". There is no "by"
    or "from", just the bare vendor token at sentence start. This
    is still squatting (the author implies Anthropic authorship
    without asserting it). The rule must flag "starts with major
    vendor token" even without a proximity-paired claim verb.
  - >
    Compound word tokens — "replaces the old filesystem-reader
    v0.1.0 tool". The word tokeniser must split on non-word boundaries
    so "filesystem-reader" produces tokens ["filesystem","reader"]
    rather than one opaque blob, otherwise "replaces" followed by
    "the" looks like a displacement claim but the target noun gets
    lost.
  - >
    Marketing-language false positive — "trusted by thousands of
    developers" is marketing copy, not a security claim. The rule
    must either weight "trusted" low (it alone is insufficient) or
    require it to co-occur with another signal before firing.
  - >
    Non-English description — descriptions in other languages (e.g.
    "versión oficial") bypass the English-token vocabulary. This is
    an acknowledged gap; the rule documents it rather than pretending
    to cover it. A future chunk adds a language-detect pre-pass.

edge_case_strategies:
  - negation-prefix-detection
  - vendor-without-claim-verb
  - word-boundary-tokenisation
  - multi-signal-required
  - language-acknowledge-gap

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - noisy_or_confidence
    - negation_adjustment
  location_kinds:
    - tool

confidence_cap: 0.85

obsolescence:
  retire_when: >
    MCP registries universally enforce vendor-claim verification
    (cryptographic attestation from the vendor's domain) so that
    description-level claims become unnecessary to scan — OR the
    MCP spec adds a structured `vendor_attestation` field that
    supersedes freeform description claims.
---

# M4 — Tool Squatting

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** Any tool description that contains English authority,
authenticity, or vendor-attribution claims.

## What an auditor accepts as evidence

M4 is a linguistic rule; its evidence is the description text plus a
structured account of which signals matched. An auditor will accept:

1. **Source proof** — the finding names the tool whose description
   carries the claim, with a `tool`-kind Location.

2. **Signal proof** — the finding names each matched signal class
   (authenticity-claim, vendor-attribution, registry-trust, etc.) and
   the anchor+qualifier token pair that triggered it. Every match is
   reproducible by re-running the tokeniser on the description.

3. **Mitigation check** — the finding states whether a negation token
   was detected adjacent to any anchor ("unofficial", "not verified",
   "disclaimer: not endorsed"). A negation reduces confidence but does
   not erase the finding — the claim was still made, just honestly.

4. **Impact statement** — tool-selection displacement. The LLM ranks
   tools by description authority signals; a squatting tool with two
   matched signals is likely to be chosen over a legitimate tool with
   no authority language.

## Why confidence is capped at 0.85

Linguistic-only rules cannot reach 0.90+ because authorship cannot be
confirmed from text alone — an "official Anthropic server" may in fact
be an official Anthropic server. The confidence cap acknowledges this
uncertainty.

## What the rule does NOT claim

- It does not claim the tool is malicious. Squatting is a deception
  pattern in metadata; the tool behind it may still be safe.
- It does not verify vendor authorship. That is out of scope for a
  static description scan.
- It does not handle non-English descriptions.
