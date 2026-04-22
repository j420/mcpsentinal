---
rule_id: L14
interface_version: v2
severity: high

threat_refs:
  - kind: paper
    id: Clarke-npm-Manifest-Confusion-2023
    url: https://blog.vlt.sh/blog/the-massive-hole-in-the-npm-ecosystem
    summary: >
      Darcy Clarke's July 2023 disclosure of npm manifest confusion.
      L14 covers the entry-point subset — bin / exports / main /
      module fields whose declared targets contradict each other or
      shadow system commands. The disclosure directly motivates
      treating entry-point fields as a first-class attack surface.
  - kind: paper
    id: Socket-exports-map-abuse-2025
    url: https://socket.dev/blog/exports-map-abuse-in-npm-packages
    summary: >
      Socket.dev 2025 research on exports map abuse — the dual-format
      payload-delivery primitive. L14 inherits this threat source
      from its parent rule L5 because the detection pathway is the
      same structural scan of the manifest's entry-point fields.
  - kind: spec
    id: CWE-426
    url: https://cwe.mitre.org/data/definitions/426.html
    summary: >
      CWE-426 — Untrusted Search Path. bin-field shadowing is the
      npm instance of this weakness: the package's bin directory is
      inserted onto PATH ahead of system binaries, redirecting
      invocations of the shadowed command to attacker-controlled
      code.

lethal_edge_cases:
  - >
    Companion emission pattern — L14 is intentionally a stub
    TypedRuleV2 whose analyze() returns []. The parent L5 rule
    emits L14 findings during its own analysis when the primitive is
    bin-system-shadow, bin-hidden-target, or exports-divergence. The
    lethal mistake a reimplementer must avoid: re-running the
    entry-point scan here would double-emit findings for every
    manifest.
  - >
    If L14 is ever un-stubbed (for example to add an entry-point
    check that L5 does not cover — main/module divergence, browser-
    field override), the new logic must NOT overlap with L5's
    bin-system-shadow, bin-hidden-target, or exports-divergence
    primitives, or the same manifest would fire twice.
  - >
    A future migration might move L14 findings OUT of L5 into this
    file. In that case the charter-traceability guard requires
    updating both the CHARTER lethal_edge_cases AND the L5 CHARTER
    in the same commit, so the two charters stay in agreement about
    which rule emits which finding.

edge_case_strategies:
  - companion-stub-emission
  - non-overlap-with-parent
  - future-migration-coordination

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - parent_rule_emits
  location_kinds:
    - config
    - source

obsolescence:
  retire_when: >
    L5 is retired (the entry-point primitives stop being observable
    in the ecosystem) OR the rule is un-stubbed with its own
    orthogonal detection surface, at which point the companion
    relationship is broken and this charter is rewritten to describe
    the new surface.

mutations_survived: []
mutations_acknowledged_blind: []
---

# L14 — Hidden Entry Point Mismatch (companion to L5)

**Author:** Senior MCP Threat Researcher.
**Applies to:** package.json manifests whose entry-point fields (bin,
exports, main, module) contradict the apparent declaration — name
shadows a system command, target filename starts with `.` or `__`,
or conditional-export branches diverge into a payload-shaped path.

## Why this rule is a stub

L14 is a **companion finding emitted by L5** (Package Manifest
Confusion). The legacy detector in `supply-chain-detector.ts`
emitted both L5 and L14 findings from a single package-manifest
analysis pass. During the v2 migration we preserved that pattern
rather than splitting the detection logic across two separate AST
walks:

- The parent L5 rule runs the manifest scan once.
- When a primitive's `emitL14Companion` flag is true
  (bin-system-shadow, bin-hidden-target, exports-divergence), L5
  emits a second RuleResult with `rule_id: "L14"` that carries the
  same EvidenceChain shape but the L14-specific remediation.

This keeps the two rule IDs independently searchable in the
findings database (reviewers filtering on "L14 entry-point
mismatch" see the same primitive L5 surfaces) without the
performance cost of a second walk.

## What the stub does

`index.ts` registers an `L14Stub` TypedRuleV2 whose analyze()
returns `[]`. The engine still recognises L14 as a registered rule
(so the engine-warning guard does not complain); findings come
from the parent L5 rule during its single analysis pass. This is
the same pattern wave-2 used for I2 (companion to I1) and
F2/F3/F6 (companions to F1).

## When to un-stub

If a future rule engineer identifies an entry-point-mismatch
primitive that L5 cannot express (for example, `browser` field
overrides that replace Node built-ins, or `module` vs `main` vs
`exports` three-way contradictions), they may un-stub L14 and give
it its own gather.ts / verification.ts. Doing so requires:

1. Removing the companion-emission path from L5 (in
   `l5-manifest-confusion/index.ts`) so L14 is the sole emitter of
   the newly-covered primitives.
2. Updating this CHARTER's `lethal_edge_cases` to describe the new
   surface.
3. Updating L5's CHARTER to note the no-longer-companion
   relationship.

Until then, L14 remains a stub and its analyze() must return `[]`.
