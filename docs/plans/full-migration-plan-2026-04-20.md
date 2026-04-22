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
- [x] **1.6 — `k-compliance-v2.ts` (K12, K14, K16, K20)** — fully complete. **1.6a K12** (`965d67c`) → `k12-executable-content-response/`. **1.6b K14** (`eb3b97a`, PR #188) → `k14-agent-credential-propagation/` with credential-vocab taxonomy + shared-state sink analysis. **1.6c K16** (`431f0f1`, PR #185) → `k16-unbounded-recursion/` with Tarjan SCC call-graph + depth-guard + cycle-breaker + 3-kind recursion edge taxonomy (direct / mutual / tool-call / emit), charter-capped 0.88 confidence. **1.6d K20** (`e046197`, PR #186) → `k20-insufficient-audit-context/` with ISO 27001 A.8.15 five-group audit-skeleton classifier (correlation / identity / tool / timestamp / outcome), confidence cap 0.85. Only K12 remains in the legacy `k-compliance-v2.ts` scaffold file. Note: original plan description misidentified the contents of `k-compliance-v2.ts` — actual rules are K12/K14/K16/K20 (not K8/K10–K13/K18, which live in supply-chain detectors).
- [x] **1.7 — `k-remaining-v2.ts` (K11, K13, K15, K18)** — commit `8dbed07` (PR #189) + fix `a4bfa06`. Migrated all four rules out of `k-remaining-v2.ts` into their own v2 dirs and deleted the legacy file: **K11** `k11-missing-server-integrity-verification/` (integrity-verification + signed-manifest coverage), **K13** `k13-unsanitized-tool-output/` (output-sanitiser taint chain), **K15** `k15-multi-agent-collusion-preconditions/` (cross-agent shared-state precondition graph), **K18** `k18-cross-trust-boundary-data-flow/` (trust-boundary taint with redactor/crypto-artifact vocabulary). Post-merge fix `a4bfa06` resolved a K18 infinite-loop in the fixed-point propagator (added kind-comparison idempotency + MAX_TAINT_ITERATIONS=32 cap) and a `jwt.sign()` false-positive (crypto-artifact producers added to redactor receiver vocabulary). Note: original plan description listed "K2, K3, K5, K14–K16, K19, K20" — actual contents of `k-remaining-v2.ts` were K11/K13/K15/K18.
- [x] **1.8 — `jsonrpc-protocol-v2.ts` (N1, N2, N3, N7, N8, N10)** — wave-2 commits `4f7594d` (N1) + `9f6284b` (N2) + `4350e5e` (N3) + `547d2c2` (N7) + `946ec94` (N8) + `b3edef9` (N10) + `f9fb4d7` (delete legacy file + wire imports) + merge `81d5e0d` + v2 remediation `a098bab` (Location conversion + CVE-2025-6515/CWE-367/CWE-400 manifest entries + isLocation test assertions) + schema-align `bfc6d04` (minimum_chain dict + canonical location_kind). Rules rebadged to match YAML intent (N3 id-collision, N7 progress-token, N8 cancellation-race, N10 handshake DoS). N4–N6/N9/N11–N15 remain in `protocol-ai-runtime-detector.ts` for a later chunk. Built against stale-base initially → remediated parallel to wave-1 A6/A7/A9 pattern. Pre-existing K20 registration gap fixed in `e86a0aa` during cleanup.
- [x] **1.9 — `advanced-supply-chain-detector.ts` (L1, L2, L6, L13)** — wave-2 commits `b095ba7` (L1) + `d804794` (L2) + `c34db82` (L6) + `64c3312` (L13) + `bfa0d3f` (tombstone L1/L2/L6/L13 classes, L7/K3/K5/K8 remain) + merge `5b9252f`. Four per-rule directories with zero regex literals, full v2 contract. CVE manifest extended: CVE-2026-27606 (Rollup path traversal, L2), CVE-2025-55155 (Shai-Hulud npm worm, L13); L1 cites already-present CVE-2025-30066. `advanced-supply-chain-detector.ts` net −601 lines.
- [ ] **1.10 — `advanced-supply-chain-detector.ts` (L7, K3, K5, K8)** — remaining rules after 1.9 migration (L1/L2/L6/L13 removed).
- [ ] **1.11 — `supply-chain-detector.ts` (L5, L12, K10)** — v1→v2
- [ ] **1.12 — `docker-k8s-crypto-v2.ts` (P1–P6)**
- [ ] **1.13 — `infrastructure-detector.ts` (P1–P7)** — split/merge decision vs 1.12
- [x] **1.14 — `secret-exfil-detector.ts` (L9, K2, G7)** — wave-2 commits `cc097c3` (L9) + `6460aee` (K2) + `2355f5d` (G7) + `b0ca925` (delete legacy file) + merge `e834b98`. Rolled own AST walker instead of `_shared/taint-rule-kit/` because the kit's positional `dangerous_args` model can't follow CVE-2025-30066's `fetch(url, {body: token})` object-property flow. CVE manifest extended: CVE-2024-52798 (path-to-regexp ReDoS, K2 pretext), CVE-2025-30066 also cited by L9. 45 tests pass. L9 uses a fixed-point taint-propagation loop through wrapper chains (`Buffer.from(x).toString("base64")`) and spreads.
- [x] **1.15 — `config-poisoning-detector.ts` (J1, L4, L11, Q4)** — wave-2 commits `ed17d40` (J1) + `d7c8fbe` (L4) + `4a30744` (L11) + `afbe21a` (Q4) + `53e278c` (delete legacy file) + merge `c2159eb`. −44 regex literals + −1 `new RegExp`. J1 uses `_shared/taint-rule-kit/` with post-filter against typed `AGENT_CONFIG_TARGETS` registry (14 hosts attributed). L4/L11/Q4 are purely structural walkers. CVE manifest extended by 5: CVE-2025-54135 (Cursor CurXecute), CVE-2025-54136 (MCPoison), CVE-2025-59536 (Claude Code consent bypass), CVE-2025-59944 (case-sensitivity bypass), CVE-2026-21852 (API-key exfil via env override). 62 tests pass.
- [x] **1.16 — `tainted-execution-detector.ts` (C4, C12, C13, C16, K9, J2)** — commits `ab813c7` (shared taint-rule-kit) + `e72e507` (C4) + `5245d38` (C12) + `ab7a6de` (C13) + `80ca4d4` (C16) + `6a965ea` (K9) + `c6d2779` (J2 + test updates) + `479f0ce` (delete tainted-execution-detector.ts) + `be5719f` (baseline/census). Every rule is in its own directory with CHARTER + sibling index + data/*.ts + __fixtures__ + __tests__. Zero regex in any of the six directories. Baseline -134 regex literals (853 → 720).
- [x] **1.17 — `c1-command-injection.ts` (C1)** — commit `b8362ca`. (Note: commit message labelled this "chunk 1.2" — the plan's chunk 1.2 is K4; C1 is 1.17.)
- [x] **1.18 — `code-security-deep-detector.ts` (C2, C5, C10, C14)** — wave-2 commits `80e222a` (C2) + `ff3a0eb` (C5) + `c59fa26` (C10) + `88924f6` (C14) + `fce2507` (delete legacy file) + merge `a63c7c6`. −35 regex literals. C2 uses `_shared/taint-rule-kit/` (file-write sinks); C10 + C14 use rule-local AST walkers (prototype-pollution = property-write sinks; JWT = call-site options-shape). Introduced reusable `SecretFormatSpec` in `c5-hardcoded-secrets/data/secret-formats.ts` — typed `Record<string, { prefix, length, charset, checksum }>` designed for reuse by future F-/L-category opaque-token detectors. 14 concrete credential formats seeded. CVE manifest extended: CVE-2019-10744 (lodash defaultsDeep), CVE-2018-3721 (lodash merge), CVE-2022-21449 (ECDSA Psychic Signatures). 57 tests pass.
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

## Completion summary (updated 2026-04-22, post wave-2)

| Phase | Done | Partial | Total | % |
|---|---:|---:|---:|---:|
| 0 | 5 | — | 5 | 100% |
| 1 | 17 | 0 | 28 | 61% |
| 2 | 0 | — | 4 | 0% |
| 3 | 0 | — | 3 | 0% |
| 4 | 0 | — | 2 | 0% |
| 5 | 0 | — | 4 | 0% |
| **Total** | **22** | **0** | **46** | **48%** |

### Completed in wave 2 (branch `claude/understand-codebase-WgIy1`, 2026-04-22)

Five migration chunks delivered in parallel sub-agents plus an orchestrator integration + 1.8 remediation pass. Net delivered: **21 new v2 rule directories**, **5 legacy detector files deleted**, **+16 CVE manifest entries**, **+276 analyzer tests** (1791 → 2067 passing, 3 skipped). Strict-mode guards (`ANALYZER_STATIC_GUARD_STRICT=true` + `ANALYZER_CHARTER_GUARD_STRICT=true`) pass across all 45 v2 charters. Typecheck clean.

| Chunk | Deliverable | Commit(s) |
|---|---|---|
| 1.8  | N1, N2, N3, N7, N8, N10 — six v2 splits + delete `jsonrpc-protocol-v2.ts` | `4f7594d`, `9f6284b`, `4350e5e`, `547d2c2`, `946ec94`, `b3edef9`, `f9fb4d7`, merge `81d5e0d`, remediation `a098bab`, schema-align `bfc6d04` |
| 1.9  | L1, L2, L6, L13 — four v2 splits + tombstone in `advanced-supply-chain-detector.ts` | `b095ba7`, `d804794`, `c34db82`, `64c3312`, `bfa0d3f`, merge `5b9252f` |
| 1.14 | L9, K2, G7 — three v2 splits + delete `secret-exfil-detector.ts` | `cc097c3`, `6460aee`, `2355f5d`, `b0ca925`, merge `e834b98` |
| 1.15 | J1, L4, L11, Q4 — four v2 splits + delete `config-poisoning-detector.ts` | `ed17d40`, `d7c8fbe`, `4a30744`, `afbe21a`, `53e278c`, merge `c2159eb` |
| 1.18 | C2, C5, C10, C14 — four v2 splits + delete `code-security-deep-detector.ts` | `80e222a`, `ff3a0eb`, `c59fa26`, `88924f6`, `fce2507`, merge `a63c7c6` |
| orchestrator | reconcile `rules/index.ts` imports + fix K20 registration gap + N-CHARTER schema align + legacy test-block cleanup + census + regex-baseline | `e86a0aa`, `bfc6d04`, `57cc8d7`, `a3852ba` |

### Wave-2 lessons (orchestration protocol addendum)

1. **Stale-worktree-base lottery** — 2 of 5 fresh Agent-tool worktrees + both 1.9 respawns landed on a pre-Phase-0 base (`8c8673f`), one commit behind main. The Agent tool branches new worktrees from `origin/main`, not from the current local branch HEAD. Fast-forwarding local `main` doesn't help. Briefings must include explicit "if HEAD is stale, `git fetch origin <branch> && git rebase FETCH_HEAD`" rather than "STOP" — 1.8 self-rebased and succeeded; three 1.9 respawns correctly aborted per "stop" briefings before the 4th landed cleanly on `a7f1af4`.
2. **v2-LITE output from stale-base work** — 1.8 sub-agent built CHARTERs + verification targets against the stale base (no `location.ts`, no `cve-manifest.json`, no `rule-standard-v2.md`), shipped prose `target: "source_code:line N:column M"` strings and skipped manifest entries, then self-rebased for the final commit. Parallel to wave-1 A6/A7/A9 audit pattern. Remediation commit `a098bab` converted targets to structured Location + added CVE/CWE manifest entries + added `isLocation` test assertions.
3. **Forbidden-file exception (rules/index.ts)** — when a sub-agent deletes a legacy detector file, it MUST update `rules/index.ts` to remove the import, otherwise the build breaks. Three of five wave-2 agents (1.8, 1.14, 1.15) followed the chunk-1.16 precedent and touched the file anyway. The orchestrator cleanup commit is still responsible for the union of imports + any new per-rule imports agents skipped (1.18 and 1.9 both left rules/index.ts untouched; orchestrator added their imports in `e86a0aa`).
4. **Orchestrator sub-agent timeout** — the orchestrator task ran for ~8 hours inside the Agent tool before the framework stopped writing to its transcript, with 15 files still uncommitted. Completion notification never arrived. Cleanup was finished in the parent session (commits `e86a0aa`/`bfc6d04`/`57cc8d7`/`a3852ba`). For wave 3+: scope orchestrator agents tighter (single task per spawn) or run integration in-session.

Five PRs merged in parallel + one hardening fix + one tombstone cleanup. Net delivered: 13 new v2 rule directories (full CHARTER + gather + verification + index + data + fixtures + tests each), two legacy files deleted (`tainted-execution-detector.ts`, `k-remaining-v2.ts`), regex literals 853 → 653 (−200, −23%). All 1791 analyzer tests green; strict-mode guards pass.

| Chunk | Deliverable | Commit(s) |
|---|---|---|
| 1.6b | K14 — `k14-agent-credential-propagation/` full v2 split | `eb3b97a` (PR #188) |
| 1.6c | K16 — `k16-unbounded-recursion/` full v2 split (Tarjan SCC + recursion taxonomy) | `431f0f1` (PR #185) |
| 1.6d | K20 — `k20-insufficient-audit-context/` full v2 split (ISO 27001 A.8.15 audit-skeleton classifier) | `e046197` (PR #186) |
| 1.7  | K11/K13/K15/K18 — four v2 splits + delete `k-remaining-v2.ts` | `8dbed07` (PR #189) |
| 1.16 | C4/C12/C13/C16/K9/J2 — six v2 splits (shared `_shared/taint-rule-kit/`) + delete `tainted-execution-detector.ts` | `45b74d8` (PR #187) |
| K18 fix | prevent infinite taint-propagation loop (kind-comparison idempotency + 32-iteration cap) + false-positive on `jwt.sign()` output (crypto-artifact producers added to redactor vocabulary) | `a4bfa06` |
| tombstone cleanup | repair stale migration breadcrumbs in `compliance-remaining-detector.ts` | `a4aa0ad` |

### Completed in prior session (branch `claude/understand-codebase-cqUGI`)

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

Wave 2 candidates: **1.18** (`code-security-deep-detector.ts`, C2/C5/C10/C14 — 4 rules) and **1.19** (`code-remaining-detector.ts`, C3/C6–C9/C11/C15 — 7 rules). Both re-use the taint-rule-kit shared infra landed in 1.16. High-density alternative: **1.20** (`description-schema-detector.ts`, 13 rules, largest single-chunk yield). Parallel-execution playbook refined in wave 1: agents run one-rule-per-worktree with typecheck + own-rule tests + strict guards only; orchestrator adds imports, regenerates census, updates plan in a single cleanup PR per wave.

---

## Open questions (from the plan's final section, not yet answered)

- **0.A** — dedupe detectors vs keep both (the 1.12/1.13, 1.9/1.10/1.11 overlaps)
- **0.B** — big-bang `engine_v2` cutover vs per-rule flag (current implementation: per-rule)
- Staffing — single pair (5 months) or two pairs (3.5 months)?
- First chunk choice — K4 per plan order, or detector-file-by-regex-density?
