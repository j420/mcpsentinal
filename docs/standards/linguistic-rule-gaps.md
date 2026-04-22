# Known Linguistic-Rule Coverage Gaps

_Established after wave-5 audit (2026-04-22). A companion to
`rule-standard-v2.md` — documents scope limits rather than standards._

## Summary

Every linguistic rule shipped through Phase 1 is tuned against an
**English-only** phrase catalogue. Token catalogues are lowercased
ASCII alphanumerics plus `_`, and phrase specs enumerate English
surface forms. A payload composed in another natural language, or
written in an English dialect that rephrases catalogue anchors, will
not match — the rule fails open.

This is a deliberate trade-off, not a bug. Non-English token
inventories would triple the maintenance surface of each catalogue,
and cross-language tokenisation is a research problem in its own
right. Phase 1 captures the bulk of documented attacks (all of which
were authored in English) and records this gap explicitly.

## Affected Rules

| Rule | Surface | Gap | Phase 2+ path |
|---|---|---|---|
| A1 — Prompt Injection in Tool Description | `tool.description` | English authority / directive vocabulary only. Non-English role-injection payloads (Japanese "無視して", Russian "игнорируй", Spanish "ignora") miss. | Add language-tagged phrase files under `a1-prompt-injection-description/data/lang/<iso>/` and extend gather to dispatch per detected script. |
| B5 — Prompt Injection in Parameter Description | `tool.input_schema.properties[*].description` | Shares A1's catalogue via the `_shared/` export — same English-only limit. | Same as A1 — B5 picks up non-English support automatically once A1's catalogue grows. |
| G2 — Trust Assertion Injection | `tool.description`, `initialize.instructions` | `G2_AUTHORITY_CLAIMS` in `_shared/ai-manipulation-phrases.ts` enumerates English authority / certification surface forms ("approved by Anthropic", "officially certified", "soc2 certified"). Non-English authority claims miss. | Extend `_shared/ai-manipulation-phrases.ts` with per-language `AUTHORITY_CLAIMS_<iso>` records and teach `gather.ts` to pick the right map by script detection. |
| G5 — Capability Escalation via Prior Approval | `tool.description` | English carry-over vocabulary ("already granted", "previously approved", "haven't revoked"). Non-English session-state injections miss. | Same pattern as G2 — per-language `PRIOR_APPROVAL_PHRASES_<iso>` records in `data/`. |
| H2 — Initialize Field Prompt Injection | `server.name`, `initialize.server_version`, `initialize.instructions` | Authority-directive catalogue is English. Unicode / base64 / LLM-special-token signals are language-agnostic and continue to work. | Extend the directive phrase catalogue with per-language variants. The Unicode and token-based signals need no change. |

## What Still Works Cross-Language

- **A6 (homoglyph)**, **A7 (zero-width)**, **A9 (encoded instructions)**
  — operate on code points / byte sequences and are not affected.
- **H2's Unicode signal, LLM-special-token signal, base64 signal** —
  also code-point / byte-level and unaffected.
- **All C-, K-, L-, M-, N-, O-, P-, Q-rules** — detect code structure
  and are language-agnostic.

## CHARTER.md Obsolescence Clauses (Reference)

Each linguistic rule's CHARTER.md `obsolescence.retire_when` clause
points back to this doc so readers see the gap without digging through
code. For G2, G5, H2, A1, B5 the clause includes the phrase:

> "English-only catalogue (see `docs/standards/linguistic-rule-gaps.md`) —
> Phase 2+ expansion will broaden language coverage."

## When to Reopen

A Phase 2 language-expansion ticket becomes worth opening when ANY of
the following conditions hold:

1. Red-team fixtures include a documented non-English injection attempt
   that current rules miss (add under
   `packages/red-team/fixtures/<lang>/`).
2. Ecosystem crawl data shows ≥5% of scanned servers publish
   non-English tool catalogues.
3. A published incident report documents a non-English MCP prompt
   injection in the wild.

Until then, the gap stays scoped and the rules remain honest about
their limits.
