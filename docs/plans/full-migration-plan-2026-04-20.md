# MCP Sentinel — Full v2 Migration Plan

_Saved: 2026-04-20_
_Branch: `claude/understand-codebase-jb0i2`_

5 phases, 40 chunks, ~19 weeks single-pair / ~3.5 months parallel-pair. Ordering is worst-first-by-value.

---

## Status legend

- [x] complete — deliverable in tree + verified this session
- [~] partial — registered `engine_v2: true` but does not yet meet the full Rule Standard v2 (no CHARTER.md in the new schema / no structured `Location` / no `gather.ts`+`verification.ts`+`index.ts` split)
- [ ] not started

---

## Phase 0 — Foundation & guardrails

- [x] **0.1 — Rule census + format specs**
  Deliverables present: `tools/scripts/rule-census.ts`, `docs/standards/rule-standard-v2.md`, `docs/census/2026-04-20.json`, `docs/census/latest.md`, `docs/cve-manifest.json`.
- [x] **0.2 — `engine_v2` flag + shadow-score column**
  v2 dispatch works: K1 and C1 are dispatched via the v2 path; v1 rules continue on v1.
- [x] **0.3 — `no-static-patterns` guard lifted to analyzer (warn-only)**
  `packages/analyzer/__tests__/no-static-patterns.test.ts` + `docs/census/regex-baseline.json` committed; baseline ratchets with each migration.
- [x] **0.4 — Charter-traceability guard (analyzer variant)**
  `packages/analyzer/__tests__/charter-traceability.test.ts` in place; enforces CHARTER.md parity for every `engine_v2: true` rule.
- [x] **0.5 — Evidence-integrity harness skeleton**
  `packages/analyzer/__tests__/evidence-integrity.test.ts` committed with `isReachable()` stub added to `taint-ast.ts`. Trivially passes until Phase 2.1 turns assertions on.

---

## Phase 1 — Migrate the 27 detector files

_Per-chunk template: charter → v2 refactor → regex→structural → Location normalisation → test matrix (≥3 pos, ≥2 neg, integrity, confidence derivation, mutation) → flip `engine_v2: true` → census diff._

- [x] **1.1 — `k1-absent-structured-logging.ts` (K1)** — commit `db51e8e`. Reference implementation for the new split directory (`CHARTER.md` + `data/` + `gather.ts` + `verification.ts` + `index.ts`).
- [x] **1.2 — `k4-missing-human-confirmation.ts` (K4)** _(EU AI Act Art.14)_ — commit `523a623`. Full v2 split; 6 threat refs, 7 lethal edge cases. 60 tests pass.
- [x] **1.3 — `k6-broad-oauth-scopes.ts` (K6)** — commit `15b00a2` (+ orphan cleanup `71f8a4a`). Full v2 split; structural first/last-segment suffix check; two-signal OAuth context resolution.
- [x] **1.4 — `k7-long-lived-tokens.ts` (K7)** — commit `be6d808`. Full v2 split; char-level duration parser (s/m/h/d/w/y/ms); per-receiver global-timeout coverage.
- [x] **1.5 — `k17-missing-timeout.ts` (K17)** — commit `02efd33`. Full v2 split; two-layer HTTP-client classification; AbortSignal scope walk; circuit-breaker dep mitigation.
- [~] **1.6 — `k-compliance-v2.ts` (K12, K14, K16, K20)** — **chunk 1.6a K12 complete** (commit `965d67c`) — split into `k12-executable-content-response/`; K14, K16, K20 still in legacy file pending chunks 1.6b/c/d. Note: original plan description misidentified the contents of `k-compliance-v2.ts` — actual rules are K12/K14/K16/K20 (not K8/K10–K13/K18, which live in supply-chain detectors).
- [ ] **1.7 — `k-remaining-v2.ts` (K2, K3, K5, K14–K16, K19, K20)**
- [ ] **1.8 — `jsonrpc-protocol-v2.ts` (N4–N15)** — 32 regex → ≤8 via JSON-RPC schema validation
- [ ] **1.9 — `l-supply-chain-v2.ts` (L1, L2, L6, L13)**
- [ ] **1.10 — `advanced-supply-chain-detector.ts` (L1–L2, L6–L7, L13, K3, K5, K8)** — v1→v2; 20 regex to drop
- [ ] **1.11 — `supply-chain-detector.ts` (L5, L12, K10)** — v1→v2
- [ ] **1.12 — `docker-k8s-crypto-v2.ts` (P1–P6)**
- [ ] **1.13 — `infrastructure-detector.ts` (P1–P7)** — split/merge decision vs 1.12
- [ ] **1.14 — `secret-exfil-detector.ts` (L9, K2, G7)** — entropy-heavy
- [ ] **1.15 — `config-poisoning-detector.ts` (J1, L4, L11, Q4)** — 19 regex; CVE-backed
- [ ] **1.16 — `tainted-execution-detector.ts` (C4, C12, C13, C16, K9, J2)**
- [x] **1.17 — `c1-command-injection.ts` (C1)** — commit `b8362ca`. (Note: commit message labelled this "chunk 1.2" — the plan's chunk 1.2 is K4; C1 is 1.17.)
- [ ] **1.18 — `code-security-deep-detector.ts` (C2, C5, C10, C14)**
- [ ] **1.19 — `code-remaining-detector.ts` (C3, C6–C9, C11, C15)**
- [ ] **1.20 — `description-schema-detector.ts` (A1–A5, A8, B1–B7)** — charter must justify residual regex as "linguistic" technique
- [x] **1.21 — `a6-unicode-homoglyph.ts` (A6, A7)** — commits `65d1f2e` + `a48b346` (sub-agent A, worktree-isolated) + `1b7bad6` (Location remediation). Full v2 split per rule: A6 + A7 live in separate directories. Initially shipped with prose-string locations; audit flagged the gap, remediated to structured `Location` kinds across all 35 link+target sites.
- [x] **1.22 — `a9-encoded-instructions.ts` (A9)** — commit `f1927e5` (sub-agent B, worktree-isolated) + `ed997d2` (CHARTER + Location remediation). Full v2 split; character-level alphabet scanners (zero regex); CHARTER rewritten to v2 frontmatter (interface_version, lethal_edge_cases, edge_case_strategies, evidence_contract, obsolescence); `toStructuredLocation()` maps internal DU to v2 Location kinds; tests assert `isLocation` on every link.
- [ ] **1.23 — `dependency-behavioral-detector.ts` (D1–D7, E1–E4)**
- [x] **1.24 — `d3-typosquatting.ts` (D3)** — commit `95002ca` (sub-agent C). Full v2 split with structured Locations from initial integration (only parallel sub-agent to produce v2-compliant Locations directly); Damerau-Levenshtein + Jaro-Winkler + visual-confusable replay; 97-entry curated target list (npm/PyPI/MCP-specific); legitimate-fork allowlist; scope-squat detection.
- [ ] **1.25 — `f1-lethal-trifecta.ts` (F1, F7 + F2/F3/F6 stubs)**
- [ ] **1.26 — `ecosystem-adversarial-detector.ts` (F4, F5, G6, H1, H3)**
- [ ] **1.27 — `ai-manipulation-detector.ts` + `g4-context-saturation.ts` (G1–G5, H2)** — adversarial-AI; do last
- [ ] **1.28 — Flip guards to failing + kill v1 adapter** (after 1.1–1.27): `no-static-patterns` warn→fail, `charter-traceability` warn→fail, delete `V1RuleAdapter`, delete `registerTypedRule`, remove `runRegexRule` / `detect.type: regex`, announce methodology v2 cutover.

---

## Phase 2 — Credibility tests

- [ ] **2.1 — Evidence-integrity harness: turn on assertions** (AST-reachability, location resolution, confidence derivation, CVE-manifest check)
- [ ] **2.2 — Adversarial mutation suite** (`mutation-runner.ts` with 8 generated AST mutations; charters declare `mutations_survived` + `mutations_acknowledged_blind`)
- [ ] **2.3 — Benign-corpus expansion 55 → 200 fixtures** (Anthropic official + Smithery top-50 + 50 canonical non-MCP + 65 edge-of-spec)
- [ ] **2.4 — Baseline precision/recall dashboard** (`accuracy.yml` extension, per-rule `target_precision`, `docs/accuracy/latest.json` + `trend.md`)

---

## Phase 3 — Compliance-agents hallucination firewall

- [ ] **3.1 — Per-rule judge triad** — 26 × 3 = 78 tests (hallucinated-pass, hallucinated-fail, genuine-confirm)
- [ ] **3.2 — LLM-replay adversarial corpus** — 20 recorded bad-LLM responses + `replay-runner.test.ts`
- [ ] **3.3 — Confidence-cap enforcement test** — every LLM-derived finding ≤ 0.85 with `analysis_technique: "llm-reasoning"`

---

## Phase 4 — CVE replay corpus

- [ ] **4.1 — Harness + 7 CVEs** — `packages/red-team/src/cve-corpus/`; CVE-2025-53109/53110, 6514, 6515, 53773, 68143/68144/68145, 2026-22785, 2026-29787
- [ ] **4.2 — Extended corpus + research attacks** — CVE-2017-5941, 2025-30066/54135/59536/59944, 2026-21852, plus Embrace-The-Red / Invariant Labs / Trail of Bits / CyberArk FSP / MPMA; auto-generate `docs/cve-coverage.md`

---

## Phase 5 — Framework reports for regulators

- [ ] **5.1 — Report data model** (`ComplianceReport` interface with attestation + canonicalised JSON)
- [ ] **5.2 — Renderers: HTML + JSON + PDF** (six framework templates: EU AI Act, ISO 27001, OWASP MCP, OWASP ASI, CoSAI, MAESTRO, MITRE ATLAS)
- [ ] **5.3 — Cross-framework kill-chain narratives** (KC01–KC07 wiring into every report)
- [ ] **5.4 — Public endpoints + attestation signing** (`/api/v1/servers/:slug/compliance/:framework.(pdf|html|json)`, HMAC signature, per-framework badge SVG)

---

## Cross-cutting guardrails (every PR enforces)

- CODEOWNERS split: `charters/` = threat-research owner; `implementations/*.ts` = engineer owner.
- Census-diff CI comment on every rule/test PR.
- Zero precision regression per rule per 2 consecutive accuracy runs.
- Every Phase 1+ rule must reference an MCP-taxonomy `Location.kind` (tool / parameter / capability / initialize / resource / prompt) or be retired.
- ADR amendments land in the same PR that changes behaviour (ADR-005 / ADR-006 / ADR-009 revisions pair with Phase 0.1 and Phase 1.28).

---

## Completion summary (updated 2026-04-21)

| Phase | Done | Partial | Total | % |
|---|---:|---:|---:|---:|
| 0 | 5 | — | 5 | 100% |
| 1 | 9 | 1 (1.6) | 28 | 32% |
| 2 | 0 | — | 4 | 0% |
| 3 | 0 | — | 3 | 0% |
| 4 | 0 | — | 2 | 0% |
| 5 | 0 | — | 4 | 0% |
| **Total** | **14** | **1** | **46** | **30%** |

### Completed this session (branch `claude/understand-codebase-cqUGI`)

| Chunk | Deliverable | Commit(s) |
|---|---|---|
| 1.2  | K4 — `k4-missing-human-confirmation/` full v2 split | `523a623` |
| 1.3  | K6 — `k6-overly-broad-oauth-scopes/` full v2 split | `15b00a2` + cleanup `71f8a4a` |
| 1.4  | K7 — `k7-long-lived-tokens/` full v2 split | `be6d808` |
| 1.5  | K17 — `k17-missing-timeout/` full v2 split | `02efd33` |
| 1.6a | K12 — `k12-executable-content-response/` full v2 split (partial chunk; K14/K16/K20 remain) | `965d67c` |
| 1.22 | A9 — `a9-encoded-instructions/` full v2 split (sub-agent B) + CHARTER/Location remediation | `f1927e5` + `ed997d2` |
| 1.24 | D3 — `d3-typosquatting/` full v2 split (sub-agent C) | `95002ca` |
| 1.21 | A6 + A7 — `a6-unicode-homoglyph/` + `a7-zero-width-injection/` full v2 splits (sub-agent A) + Location remediation | `65d1f2e` + `a48b346` + `1b7bad6` |
| baseline | Regex-baseline ratchets (×3) | `f3b3ccd` and others |

Net regex literal delta this session: **853 → 762 (−91, −11%)**. Net string-arrays > 5: **13 → 7 (−6)**.

### Post-integration audit (sub-agent D)

After the parallel sub-agents (A/B/C) integrated, a dedicated verification sub-agent ran a full v2-contract audit against the four merged rules. It quantified a **Location-shape gap** in A6/A7/A9 (sub-agents A and B had built on an old base commit that predated `location.ts`, so they shipped `location: string` instead of `location: Location`). D3 (sub-agent C) was fully v2-compliant on initial integration.

The audit's findings drove the remediation commits `ed997d2` (A9 CHARTER rewrite + Location conversion + A7 CVE-2021-42574 manifest entry) and `1b7bad6` (A6 + A7 Location conversion across all 35 link+target sites). All four rules now pass `charter-traceability.test.ts` in STRICT mode (`ANALYZER_CHARTER_GUARD_STRICT=true`) and assert `isLocation(...)` on every evidence link and verification-step target in their own test suites.

**Chunk 1.28 (guard flip + V1RuleAdapter deletion) is UNBLOCKED** with respect to the 10 rules migrated so far (K1, K4, K6, K7, K12, K17, C1, A6, A7, A9, D3). The remaining ~97 rules still ride the legacy path.

### Parallel-execution playbook (validated this session)

Running 3 migration sub-agents in parallel worked, but with two discovered constraints:

1. **Worktree base commit** — git worktrees from the Agent tool can land on an older base than the parent session's branch. Sub-agents A and B checked out at commit `8c8673f` (pre-Phase-0), so they could not read `location.ts`, `rule-standard-v2.md`, `cve-manifest.json`, or the K1/K4 reference implementations. Future parallel runs must either brief each agent with a minimal self-contained Location-kind reference, or integrate the agent's work through a merge into an up-to-date branch before review.
2. **Verification sub-agent D is load-bearing** — without the audit, A6/A7/A9 would have shipped as v2-lite (CHARTER + chain + factors + steps, but prose locations). The audit caught the gap before the guard flip would have hard-failed CI.

### Next chunk

Per plan order: 1.6b K14 (Agent Credential Propagation via Shared State) — fills out the remainder of `k-compliance-v2.ts`. Alternative leverage picks: 1.16 (`tainted-execution-detector.ts`, 6 rules, reuses C1 taint pattern) or 1.20 (`description-schema-detector.ts`, 13 rules, largest single-chunk yield).

---

## Open questions (from the plan's final section, not yet answered)

- **0.A** — dedupe detectors vs keep both (the 1.12/1.13, 1.9/1.10/1.11 overlaps)
- **0.B** — big-bang `engine_v2` cutover vs per-rule flag (current implementation: per-rule)
- Staffing — single pair (5 months) or two pairs (3.5 months)?
- First chunk choice — K4 per plan order, or detector-file-by-regex-density?
