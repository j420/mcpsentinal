# Package: scorer

**Purpose:** Compute composite 0–100 security scores from findings. Pure function — no DB access, no side effects.

## Key Files
- `src/scorer.ts` — `computeScore()` function
- `src/__tests__/scorer.test.ts` — tests

## The Algorithm (do not change without reading scoring-algorithm.md)

```
Score = 100 - Σ(penalty per finding)

Severity weights:
  critical     → -25
  high         → -15
  medium       → -8
  low          → -3
  informational → -1

Floor: 0   (score never goes below 0)
Ceiling: 100 (score never goes above 100)
Lethal Trifecta (F1): if detected, total score CAPPED at 40
```

**The weights are defined in `agent_docs/scoring-algorithm.md`.**
The `SEVERITY_WEIGHTS` constant in `scorer.ts` must always match that document.
If you change a weight: update BOTH files simultaneously, or the registry's scores become unexplainable.

## Sub-scores

Five category sub-scores each start at 100 and are reduced independently:

| Sub-score | Driven by rule categories |
|---|---|
| `code_score` | code-analysis (C1–C16) |
| `deps_score` | dependency-analysis (D1–D7) |
| `config_score` | schema-analysis (B1–B7) + ecosystem-context (F1–F7) |
| `description_score` | description-analysis (A1–A9) |
| `behavior_score` | behavioral-analysis (E1–E4) |

G and H category rules map to `config_score` (via CATEGORY_MAP fallback).

## OWASP Coverage Map
`owasp_coverage` is a `Record<string, boolean>`:
- `true` = no findings in that OWASP category = **clean**
- `false` = has findings = **at risk**

Used by the public registry to show OWASP posture at a glance.

## What NOT to Do
- Do NOT change `SEVERITY_WEIGHTS` without updating `agent_docs/scoring-algorithm.md`
- Do NOT add DB access — this is a pure function
- Do NOT add LLM scoring — all scoring is deterministic (ADR-006)
- Do NOT change the lethal trifecta cap threshold (40) without product approval
