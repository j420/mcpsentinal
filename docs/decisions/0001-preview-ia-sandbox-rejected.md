# DR-001 — `/preview` IA Sandbox Rejected

| | |
|---|---|
| **Status** | Rejected |
| **Date** | 2026-04-27 |
| **Branch where attempted** | `claude/understand-codebase-Sjl70` |
| **Build commit** | `ce8dd7a feat(web): /preview information-architecture sandbox` |
| **Revert commit** | `b326ebc revert: remove /preview IA sandbox` |
| **Original PR** | [#208 — closed without merge](https://github.com/j420/mcpsentinal/pull/208) |

---

## Context

A site audit of the public registry identified four information-architecture
problems on the live tree:

1. `/` and `/servers` are both server lists with the same data and filters,
   differing only in layout (table vs card grid).
2. `/categories/[category]` is `/servers?category=X` with a different layout
   — even the SVG icon definitions are copy-pasted between the two pages.
3. `/taxonomy`, `/compliance`, and parts of `/about` all enumerate the same
   detection-rule set in three different shapes.
4. `/dashboard` and `/attack-chains` — the most differentiated screens —
   are not reachable from the top navigation.

A five-slot IA proposal was drafted in response: **Servers · Ecosystem ·
Intelligence · Methodology · Scanner**.

---

## What Was Attempted

A parallel route tree at `/preview/*` was built so the new IA could be
walked end-to-end without modifying any live route.

- 13 new files under `packages/web/src/app/preview/`
- 4 lines added to `packages/web/src/app/robots.ts` (disallow `/preview/`)
- Zero edits to existing components, layouts, or pages
- Designed to be removable via two commands:
  ```
  rm -rf packages/web/src/app/preview/
  git checkout main -- packages/web/src/app/robots.ts
  ```

**Built** (functional pages):
- `/preview` — IA proposal home with live ecosystem stats
- `/preview/servers` — canonical list with the score column the live page omits, with honest "Awaiting scan" treatment when score data is absent
- `/preview/methodology` — single landing consolidating `/taxonomy` + `/compliance` + the methodology sections of `/about`

**Stubbed** (one-screen pointers to the live equivalent so the IA was
fully navigable without breaking anything):
- `/preview/ecosystem` → `/dashboard`
- `/preview/intelligence` → `/attack-chains`
- `/preview/scanner` → `/scanner`
- `/preview/about` → `/about`

The work was committed (`ce8dd7a`), pushed, and opened as PR #208.

---

## Decision

**Rejected.** PR #208 was closed without merging. Commit `b326ebc`
reverted the entire `/preview` tree from the branch. `main` was never
modified.

---

## Reasoning

The user reviewed the approach and indicated it did not land. A specific
written objection was not captured before removal, so this section
documents factors worth noting for any future IA-experimentation work,
not a definitive root cause.

Possible contributing factors:

1. **Process.** The work was implemented, committed, and PR'd before any
   visual mockup or written proposal was shared for review. A design
   review on a static mockup before code lands would have surfaced any
   directional disagreement earlier and at lower cost.
2. **Approach.** A parallel `/preview/*` namespace may not be the right
   primitive for IA experimentation in this repository — it inherently
   creates two navigations and two visual treatments side by side, which
   can make the proposal harder to evaluate rather than easier.
3. **Scope.** Seven preview routes (three real + four stubs) were built
   in a single PR. A smaller, single-page proposal would have made the
   directional question easier to evaluate.

---

## Consequences

- `main` is unaffected.
- Branch `claude/understand-codebase-Sjl70` retains the build → revert
  arc as historical record. The branch's net diff against `main` is
  empty.
- PR #208 remains closed and visible for anyone wanting to see what was
  attempted.
- No code in the repository imports from or references the removed
  `packages/web/src/app/preview/` path.

---

## What This Means for Future IA Work

The four IA problems identified in the audit are real and remain
unaddressed:

- `/` and `/servers` duplication
- `/categories/[category]` redundancy
- detection-rule taxonomy split across three pages
- `/dashboard` and `/attack-chains` invisible from the navigation

If a future round of IA work is undertaken, recommended starting points
based on what was learned here:

1. **Begin with a written proposal or static mockup**, not a code branch.
2. **Pick one specific IA problem and propose one specific change** —
   resist the temptation to redesign the whole navigation in one PR.
3. **Validate the directional question with the user** before any code
   lands. The cost of a one-page mockup is low; the cost of seven
   committed preview routes is higher and was not absorbed gracefully.
4. **Avoid parallel `/preview/*` route trees.** If an experimental
   approach is desired, prefer a feature branch + Vercel/Railway preview
   deployment (which already gives reviewers a unique URL per PR)
   over a parallel route tree in the same deployment.

---

## Cross-References

- PR #208 — https://github.com/j420/mcpsentinal/pull/208
- Build commit — `ce8dd7a`
- Revert commit — `b326ebc`
