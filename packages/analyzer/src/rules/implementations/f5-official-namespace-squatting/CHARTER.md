---
rule_id: F5
interface_version: v2
severity: critical

threat_refs:
  - kind: paper
    id: Birsan-2021-Dependency-Confusion
    url: https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
    summary: >
      Alex Birsan (Feb 2021) demonstrated RCE against 35+ major
      organisations by registering internal-looking package names on
      public registries. The technique generalises from package names
      to any namespace developers implicitly trust — MCP server names
      among them. A server called "anthropic-filesystem-mcp" is
      indistinguishable from an official Anthropic product to the
      user inspecting their AI client's server list, and is indistinguishable
      to the LLM when deciding whether to call its tools. F5 shares the
      Birsan threat model with D7 (scoped high-version attacks) and
      D3 (typosquatted dependency names).
  - kind: paper
    id: Wiz-2025-MCP-Supply-Chain
    url: https://www.wiz.io/blog/mcp-supply-chain
    summary: >
      Wiz Research (2025) documented real namespace-confusion incidents
      in the MCP ecosystem — third-party servers ingesting the Anthropic,
      OpenAI, Google, or GitHub brand to bootstrap trust. The report
      highlights that MCP clients (Claude Desktop, Cursor, Claude Code)
      surface the server name verbatim in their approval dialog, and
      users accept a brand-matching server as "official" without
      inspecting the repository origin. F5 is MCP Sentinel's structural
      response to that research.
  - kind: paper
    id: Socket-2025-MCP-Typosquat-Wave
    url: https://socket.dev/blog/typosquat-mcp-sdk-wave
    summary: >
      Socket.dev (2025) documented a wave of typosquats of
      @modelcontextprotocol/sdk (notably @mcp/sdk, mcp-sdk, fastmcp-sdk).
      Those are package typosquats (covered by D3) but the same attacker
      cohort is the natural author of a namespace-squat attack against
      server names on the Smithery registry. F5 closes the sister-gap
      at the server-name surface.
  - kind: spec
    id: OWASP-MCP10-Supply-Chain
    url: https://owasp.org/www-project-top-10-for-large-language-model-applications/
    summary: >
      OWASP MCP Top 10 — MCP10 Supply Chain. Namespace squatting is
      explicitly called out as a supply-chain compromise vector. A
      server claiming an official vendor namespace without publisher
      proof is a direct MCP10 indicator the scanner must surface.
  - kind: spec
    id: MITRE-ATLAS-AML-T0054
    url: https://atlas.mitre.org/techniques/AML.T0054
    summary: >
      MITRE ATLAS AML.T0054 — LLM Prompt Injection. Namespace squatting
      is an indirect prompt-injection enabler: once the user approves
      the impersonator server, the squatter's tool descriptions,
      instructions, and outputs flow into the LLM's context with the
      trust associated with the impersonated vendor.

lethal_edge_cases:
  - >
    Damerau-Levenshtein distance 1 from an official vendor name —
    "anthropc", "googl", "microsft" are typosquats a reviewer would
    read past. The rule must flag these at the highest confidence
    band: edit-distance-one from a high-value namespace is a
    dominant supply-chain signal.
  - >
    Visual-confusable substitution — "l" → "1" ("goog1e"), "o" → "0"
    ("micr0soft"), "I" → "l" ("lBM") — distance-2 in byte space but
    visually indistinguishable in a monospaced approval dialog. The
    rule must apply the same visual-confusable replay as D3 to catch
    these without requiring a curated list of every visual variant.
  - >
    Substring containment without an official repository link — a
    server named "anthropic-filesystem-mcp" contains "anthropic"
    verbatim. If the github_url is not under github.com/anthropics/,
    the server is impersonating the namespace regardless of the
    owner's intent (accidental squats are still squats, because the
    trust they hijack is real).
  - >
    Legitimate impersonation — a third-party server that IS an
    officially-approved partner of the vendor (think: Anthropic
    Marketplace partners). The rule cannot distinguish approved
    partners from squatters statically; it emits the finding and
    documents the no_publisher_match signal so a reviewer can
    dismiss with organisational context.
  - >
    Homoglyph attack — Cyrillic "а" (U+0430) inside "аnthropic"
    renders identically to Latin "a" (U+0061) in most terminal
    fonts. The rule must normalise Unicode confusables before
    similarity comparison (shared with D3's Unicode path) so the
    homoglyph variant does not silently evade the check.
  - >
    Plural/possessive — "anthropics-mcp" (the real Anthropic GitHub
    org is `anthropics`) versus "anthropic-mcp" (singular, shared
    with the company brand). Both land inside distance-1 of the
    other; the rule must not flag `anthropics` as a squat of
    `anthropic` when the github_url confirms the legitimate org.

edge_case_strategies:
  - levenshtein-distance-band
  - visual-confusable-replay
  - substring-containment-check
  - publisher-url-verification
  - unicode-normalisation

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - official_namespace_signal
  location_kinds:
    - tool
    - capability

obsolescence:
  retire_when: >
    Every MCP client enforces a publisher-signature check against a
    trust root (vendor-owned public keys) before displaying a server
    name that contains a reserved namespace prefix — AND the Smithery
    / Glama / Official MCP registry reject submissions whose names
    contain a vendor-reserved substring unless the submitter proves
    ownership via the trust root. Under those conditions F5's
    structural signal is redundant.

mutations_survived:
  - split-string-literal
  - unicode-homoglyph-identifier
  - base64-wrap-payload
  - reorder-object-properties
mutations_acknowledged_blind: []
---

# F5 — Official Namespace Squatting

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** Any MCP server whose server metadata has been collected
by the scanner — `context.server.name` + `context.server.github_url`.
The check is metadata-only and does not require source code.

## What an auditor accepts as evidence

A supply-chain auditor (OWASP MCP10, MITRE ATLAS AML.T0054) will not
accept "name looks like anthropic". They will accept a finding that
says:

1. **Similarity proof** — the finding cites the server name as a
   tool-kind Location and records the reproducible Damerau-Levenshtein
   distance to the matched vendor namespace. If the match is a
   substring containment or a visual-confusable variant, the rule
   records which classifier produced it. The auditor can recompute
   the numbers from the names alone.

2. **Publisher-mismatch proof** — the finding records whether the
   server's github_url is under the vendor's known GitHub
   organisation (e.g. `github.com/anthropics/` for Anthropic). If
   the URL matches, the rule does NOT fire. If the URL is missing
   or unrelated, the finding documents the mismatch as evidence.

3. **Impact statement** — concrete description: MCP clients surface
   the server name verbatim in approval dialogs. The LLM consumes the
   server name, its tool descriptions, and its serverInfo in the same
   context window. A name that implies official vendor origin hijacks
   the trust the user would extend to the real vendor — a supply-chain
   attack disguised as a legitimate install.

## What the rule does NOT claim

- It does not claim the server is malicious. A namespace-squat finding
  is a structural mismatch between the claimed namespace and the
  publisher identity. The reviewer inspects the repository owner,
  publication history, and vendor confirmation to decide intent.
- It does not check live registry state (trust-root signatures,
  Smithery-verified badges). That belongs in a future runtime-audit
  chunk; F5 is a static signal.

## Why confidence is capped at 0.90

Similarity-plus-publisher-mismatch is strong but not definitive:

- a vendor-approved partner may legitimately use the vendor's
  namespace in their server name with a contractual relationship the
  scanner cannot observe;
- the rule's vendor-org mapping is a curated list and may lag behind
  an org rename (github.com/anthropics → github.com/anthropic-pbc);
- the github_url may be missing for reasons unrelated to squatting
  (self-hosted, private mirror), producing a publisher-mismatch
  signal that is non-material.

Capping at 0.90 preserves explicit room for those externalities.

## Relationship to D3 and D7

- D3 (Typosquatting Risk) operates on package dependency names.
- D7 (Dependency Confusion) flags scoped packages with artificially
  high version numbers.
- F5 (this rule) operates on the SERVER name in the MCP registry.
  The three rules share the Birsan threat model but operate on
  different registry surfaces; a server that typosquats both its
  package name AND its server name produces all three findings
  and that is the intended behaviour.
