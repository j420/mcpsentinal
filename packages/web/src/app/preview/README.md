# `/preview` — Experimental Information Architecture

This directory is a **parallel, removable** route tree that proposes a cleaner
information architecture for the public registry.

## Why it exists

The live site has 14 routes, four of which duplicate work
(`/` and `/servers` are both server lists; `/categories/[category]` is just
`/servers?category=X` with a different layout; `/taxonomy`, `/compliance` and
`/about` all enumerate the same rule set in different shapes), and the most
differentiated screens (`/dashboard`, `/attack-chains`) are not in the nav.

Rather than refactor the live tree in place — which would risk
SEO regressions, broken inbound links, and a long PR — this `preview/`
directory builds the proposed IA alongside the existing one. Both work.
Nothing in the live tree is touched.

## What's here

- `layout.tsx` — preview chrome (banner, new nav, footer). Hides the root
  layout's site header/footer for `/preview/*` routes only, via a scoped
  `<style>` block. Removing this directory restores the root layout for
  every route.
- `_components/` — preview-only chrome components. Not exported elsewhere.
- `page.tsx` — preview home.
- `servers/page.tsx` — canonical server list (Bucket 2 work — adds the
  score column the live `/servers` is missing).
- `methodology/page.tsx` — landing that consolidates `/taxonomy` +
  `/compliance` + the rule/scoring sections of `/about` into one IA slot.
  Links out to the live deep pages for now; deeper consolidation is a
  follow-up PR.
- `ecosystem/page.tsx`, `intelligence/page.tsx`, `scanner/page.tsx`,
  `about/page.tsx` — placeholders that route to the existing live pages
  while keeping the user inside the new IA. They will be filled in PR by PR.

## Non-negotiables

- **The live site is not modified.** Existing routes (`/`, `/servers`,
  `/categories`, `/categories/*`, `/about`, `/dashboard`, `/attack-chains`,
  `/compliance`, `/taxonomy`, `/scanner`, `/server/[slug]`,
  `/responsible-disclosure`, `/not-found`) render exactly as they did before
  this directory existed.
- **Search engines do not index `/preview/*`** — `robots.ts` adds it to the
  disallow list. Removing `/preview` makes that line a no-op.
- **No new dependencies.** Everything reuses components already in
  `packages/web/src/components/`.
- **Server components only.** No client-side state. Matches the existing
  bundle-leanness rule in `packages/web/CLAUDE.md`.

## How to access it

`https://mcp-sentinel.com/preview` (or `http://localhost:3000/preview` in dev).
There is intentionally no link from the live nav until the team decides to
promote it.

## How to remove it

```
rm -rf packages/web/src/app/preview/
git checkout packages/web/src/app/robots.ts
```

That's it. No other files in the repository reference this directory.

## How to promote it

When the new IA is ready to replace the current one:

1. Move the contents of each `preview/<route>/` into the matching live route.
2. Add 301 redirects from any retired URLs (`/server/[slug]`,
   `/categories/[category]`) in `next.config.ts`.
3. Delete this directory and the robots.ts disallow.
4. Update `sitemap.ts` to drop the retired URLs.

Promotion is a single, reviewable PR — nothing in the codebase is locked in
to `/preview` paths because no other code imports from here.
