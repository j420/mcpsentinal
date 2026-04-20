# Rule Standard v2

**Status:** Draft — adopted by Phase 0, Chunk 0.1. Enforced rule-by-rule as
Phase 1 migrations land (tracked by `docs/census/latest.md`).

This document is the contract that every v2 detection rule must satisfy.
It is binding on new rules written after this lands, and aspirational for
existing rules — each migration chunk in Phase 1 converts exactly one
detector file to full v2 compliance.

The contract has four parts:

1. **Dual-persona authoring** — every rule has a `CHARTER.md` (Senior MCP
   Threat Researcher) and a sibling `index.ts` / `<rule>.ts` (Senior MCP
   Security Engineer).
2. **Structured locations** — evidence links point to `Location` discriminated
   union values, not prose strings.
3. **Threat references with a CVE manifest** — every rule cites at least
   one verifiable public reference, validated against `docs/cve-manifest.json`.
4. **Verification steps that reference a `Location`** — an auditor must be
   able to open the cited position and reproduce the observation.

These four guarantees are what make findings admissible as audit evidence
under EU AI Act Art. 12 (record-keeping), ISO 27001 A.8.15 (logging
adequacy), and ISO 42001 A.8.1 (AI system transparency).

---

## 1. CHARTER.md — Frontmatter Schema

Every v2 rule directory contains a `CHARTER.md` adjacent to the TypeScript
implementation. The charter is written in the **Senior MCP Threat Researcher**
voice and declares — in structured YAML frontmatter — the contract the
implementation must satisfy. The mirror of `charter-traceability.test.ts`
(Phase 0, Chunk 0.4) mechanically enforces consistency between the charter
and the code.

```yaml
---
# Required — primary identity
rule_id: K1                                     # must match the TypedRule's id
interface_version: v2                           # v2 is mandatory for new rules
severity: high                                  # must match YAML metadata

# Required — threat research
threat_refs:                                    # at least one entry required
  - kind: cve                                   # cve | paper | incident | spec
    id: CVE-2025-53773                          # for cve kind, must exist in cve-manifest.json
    url: https://nvd.nist.gov/vuln/detail/CVE-2025-53773
  - kind: paper
    id: CyberArk-FSP-2025
    url: https://www.cyberark.com/…
    summary: >                                  # required for non-cve kinds
      Full Schema Poisoning demonstration

# Required — what makes this rule honest
lethal_edge_cases:                              # minimum 3
  - Payload split across nested object values
  - Unicode control characters (U+202E) between tokens
  - Base64-wrapped instruction inside a comment field
edge_case_strategies:                           # names must appear in testStrategies()
  - structural-split-payload
  - unicode-evasion
  - encoded-payload

# Required — evidence contract
evidence_contract:
  minimum_chain:                                # which chain links are mandatory
    source: true                                # someone or something that introduces risk
    propagation: false                          # optional — only when data flows across links
    sink: true                                  # where the impact materialises
    mitigation: false                           # optional — present if evidence of partial defence
    impact: true                                # what an attacker gains if unmitigated
  required_factors:                             # confidence factors this rule must emit
    - token_similarity_to_known_attack
    - unmitigated_sink_reachability
  location_kinds:                               # allowed Location kinds in any link (see §2)
    - source
    - tool
    - schema

# Required — how to kill this rule
obsolescence:
  retire_when: >
    MCP spec 2027 mandates server-side schema validation that makes
    parameter-level injection uncollectible.
---

# Charter: K1 — Absent Structured Logging
…
```

**Enforcement:** `packages/analyzer/__tests__/charter-traceability.test.ts`
(Chunk 0.4) parses every charter and asserts: `rule_id` matches the
`TypedRule.id` exported from the sibling `.ts`; each `edge_case_strategies`
entry is present in `testStrategies()` (v2 rules) or a documented
`edgeCaseStrategies` constant (v1 adapters); each `cve` entry exists in
`docs/cve-manifest.json`.

---

## 2. The `Location` Discriminated Union

Every evidence link (source, propagation, sink, mitigation, impact) must
carry a `Location` — a structured position an auditor can navigate to.
**Prose locations ("tool approval dialog", "the initialize response") are
no longer acceptable.**

```ts
// packages/analyzer/src/rules/location.ts (to be added in Chunk 0.5)

export type Location =
  | { kind: "source";       file: string; line: number; col?: number; length?: number }
  | { kind: "tool";         tool_name: string }
  | { kind: "parameter";    tool_name: string; parameter_path: string }
  | { kind: "schema";       tool_name: string; json_pointer: string }
  | { kind: "dependency";   ecosystem: "npm" | "pypi" | "go" | "rubygems" | "cargo"; name: string; version: string }
  | { kind: "config";       file: string; json_pointer: string }
  | { kind: "initialize";   field: "server_name" | "server_version" | "instructions" }
  | { kind: "resource";     uri: string; field?: "name" | "description" | "uri" | "mimeType" }
  | { kind: "prompt";       name: string; field?: "name" | "description" | "argument" }
  | { kind: "capability";   capability: "tools" | "resources" | "prompts" | "sampling" | "logging" };
```

**Rules of use:**

- `source` with `file/line/col` is the canonical position. Extractors that
  can only recover `file/line` (no column) set `col: undefined` — not `0`.
- `parameter_path` is a JSON path expression (e.g. `input_schema.properties.cmd`).
- `json_pointer` is RFC 6901 (e.g. `/properties/args/items/0`).
- The charter's `evidence_contract.location_kinds` is a whitelist —
  linking to an out-of-whitelist kind is a guard failure.

**Migration rule:** when a Phase 1 chunk migrates a detector file, all
existing prose locations in that file must be replaced with `Location`
values. Adapters may continue to emit `{ kind: "source", file: "unknown", line: 0 }`
during the migration window, but the `evidence-integrity` test
(Chunk 0.5) will count those as "unresolved" and the file's migration is
not complete until that count is zero.

---

## 3. Threat References + CVE Manifest

Every `EvidenceChain` must carry at least one `ThreatReference`. Every
`ThreatReference` of kind `cve` must resolve to an entry in
`docs/cve-manifest.json` — a source-controlled, append-only list of CVEs
the codebase cites.

```jsonc
// docs/cve-manifest.json — seed shape
{
  "version": 1,
  "last_updated": "2026-04-20",
  "entries": [
    {
      "id": "CVE-2025-53109",
      "title": "Anthropic filesystem server root boundary bypass",
      "disclosed": "2025-07-14",
      "cvss_v3": 8.1,
      "advisory_url": "https://nvd.nist.gov/vuln/detail/CVE-2025-53109",
      "cited_by_rules": ["I4", "I11"]
    },
    {
      "id": "CVE-2026-22785",
      "title": "Orval OpenAPI MCP generator code injection",
      "disclosed": "2026-02-11",
      "cvss_v3": 9.1,
      "advisory_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-22785",
      "cited_by_rules": ["J7"]
    }
  ]
}
```

**Rules of use:**

- Adding a new CVE citation requires adding the entry to the manifest in
  the same PR. `charter-traceability` fails the test run otherwise.
- `cited_by_rules` is advisory only — the authoritative source is the
  `threat_refs` block in each charter. The manifest's `cited_by_rules`
  is rebuilt by a generator script after Phase 0 lands.
- Non-CVE references (`kind: paper | incident | spec`) must have a `url`
  and a `summary` ≥ 40 characters. No blind URLs.

---

## 4. VerificationStep with `target: Location`

`EvidenceChain.verification_steps` is where the rule teaches an auditor how
to reproduce the observation. v2 requires every step to carry a structured
`target` (a `Location`) — not just a prose description.

```ts
export interface VerificationStep {
  step: number;
  /** Prose explanation, audience = auditor with access to the server source. */
  description: string;
  /** Where exactly to look. A reader can paste this into jump-to-definition. */
  target: Location;
  /** What the auditor will observe after performing the step. */
  expected_observation: string;
}
```

**Contract:** a chain of n verification steps must reach the sink. The first
step's `target` should equal (or be a prefix of) the chain's `source`
location; the last step's `target` should equal the chain's `sink` location.
A chain whose steps do not connect source to sink is considered
unreachable and is downgraded to `confidence ≤ 0.40` by the engine.

---

## 5. Enforcement Timeline

| Enforcement | Chunk | Mode |
|---|---|---|
| Rule census baseline | 0.1 | informational only |
| `engine_v2: false` default; per-rule opt-in | 0.2 | non-breaking |
| `no-static-patterns` mirrored in analyzer | 0.3 | **warn-only** |
| `charter-traceability` mirrored in analyzer | 0.4 | **warn-only** |
| `evidence-integrity` test skeleton | 0.5 | skipped until Phase 1 |
| Per-rule migration to v2 | Phase 1 (chunks 1.1–1.27) | **enforcing** for the touched rule |
| Global enforcement flip | end of Phase 1 | `no-static-patterns` fails CI for any `src/rules/` file that is not on the exempt list (baseline) |

**The baseline list:** `docs/census/regex-baseline.json` (written in
Chunk 0.3) records the regex counts today. The guard fails only for files
that are **above** baseline. Phase 1 reduces the baseline to zero one file
at a time.

---

## 6. What a v2 rule looks like — reference structure

```
packages/analyzer/src/rules/implementations/
└── k1-absent-structured-logging/
    ├── CHARTER.md                     ← threat researcher persona, frontmatter + narrative
    ├── index.ts                       ← TypedRuleV2 class, registers into engine
    ├── gather.ts                      ← deterministic evidence gathering (AST + graph)
    ├── verification.ts                ← VerificationStep builders
    ├── __fixtures__/
    │   ├── true-positive-01.ts        ← minimal MCP server triggering the rule
    │   ├── true-positive-02.ts
    │   ├── true-negative-01.ts
    │   └── benign-production-01.ts    ← from the 55-fixture benign corpus
    └── __tests__/
        ├── index.test.ts              ← functional tests (fires / does not fire)
        └── judge-triad.test.ts        ← three-case pattern from Chunk 0.4 design
```

Chunk 1.1 converts `k1-absent-structured-logging.ts` to this shape as the
reference implementation; chunks 1.2–1.27 follow the same template.

---

## 7. Why these four requirements and not more

Five requirements were considered and rejected:

- **Mandatory LLM synthesis per rule** — rejected. LLM use is scoped to
  `packages/compliance-agents/` per ADR-009. Analyzer rules stay deterministic.
- **Mandatory mutation-suite coverage per rule** — deferred to Phase 3.
  Phase 1's priority is correctness of the normal path; mutation coverage
  belongs to a hardening phase.
- **Machine-readable remediation with CWE/CAPEC IDs** — deferred. Adds
  schema complexity without buying audit admissibility. Phase 5 revisits.
- **Per-rule precision/recall floor in CI** — already enforced by
  `accuracy.yml` at the category level; a per-rule floor would require
  per-rule fixture volume we don't yet have.
- **Automated compliance narrative generation** — owned by
  `packages/compliance-agents/`, not the analyzer.

The four requirements that remain are the minimum for an auditor to
accept a finding as evidence. Anything less and the finding is hearsay.
