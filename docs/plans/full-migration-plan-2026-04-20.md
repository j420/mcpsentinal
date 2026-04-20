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
- [ ] **1.2 — `k4-missing-human-confirmation.ts` (K4)** _(EU AI Act Art.14)_ — partial pre-Standard v2 registration; needs CHARTER.md + Location migration.
- [ ] **1.3 — `k6-broad-oauth-scopes.ts` (K6)**
- [ ] **1.4 — `k7-long-lived-tokens.ts` (K7)**
- [ ] **1.5 — `k17-missing-timeout.ts` (K17)**
- [ ] **1.6 — `k-compliance-v2.ts` (K8, K10–K13, K18)** — 26 regex → ≤5
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
- [ ] **1.21 — `a6-unicode-homoglyph.ts` (A6, A7)**
- [ ] **1.22 — `a9-encoded-instructions.ts` (A9)**
- [ ] **1.23 — `dependency-behavioral-detector.ts` (D1–D7, E1–E4)**
- [ ] **1.24 — `d3-typosquatting.ts` (D3)**
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

## Completion summary (2026-04-20)

| Phase | Done | Total | % |
|---|---:|---:|---:|
| 0 | 5 | 5 | 100% |
| 1 | 2 | 28 | 7% |
| 2 | 0 | 4 | 0% |
| 3 | 0 | 3 | 0% |
| 4 | 0 | 2 | 0% |
| 5 | 0 | 4 | 0% |
| **Total** | **7** | **46** | **15%** |

### Completed this session

| Chunk | Deliverable | Commit |
|---|---|---|
| 0.1 | `tools/scripts/rule-census.ts` + `docs/standards/rule-standard-v2.md` | earlier |
| 0.2 | `engine_v2` flag, v2 dispatch, shadow score column | earlier |
| 0.3 | `no-static-patterns.test.ts` + `regex-baseline.json` | earlier |
| 0.4 | `charter-traceability.test.ts` (analyzer variant) | earlier |
| 0.5 | `evidence-integrity.test.ts` skeleton + `isReachable` stub | earlier |
| 1.1 | K1 — `k1-absent-structured-logging/` full v2 split | `db51e8e` |
| 1.17 | C1 — `c1-command-injection/` full v2 split | `b8362ca` |

### Next chunk

Plan order says 1.2 (K4, EU AI Act Art.14). Alternative: 1.16 (`tainted-execution-detector.ts`, 6 rules) reuses the C1 taint pattern just validated — more leverage per PR.

---

## Open questions (from the plan's final section, not yet answered)

- **0.A** — dedupe detectors vs keep both (the 1.12/1.13, 1.9/1.10/1.11 overlaps)
- **0.B** — big-bang `engine_v2` cutover vs per-rule flag (current implementation: per-rule)
- Staffing — single pair (5 months) or two pairs (3.5 months)?
- First chunk choice — K4 per plan order, or detector-file-by-regex-density?
