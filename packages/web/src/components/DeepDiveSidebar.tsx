"use client";

/**
 * DeepDiveSidebar — sticky left rail for the deep-dive page.
 *
 * Cluster D, part 5/5. Owns four pieces of interactive state:
 *
 *   1. fuzzy search box (debounced URL writeback)
 *   2. multi-select severity + framework chip filters (instant URL writeback)
 *   3. two boolean toggles ("only failing rules", "include skipped")
 *   4. IntersectionObserver-driven scroll-spy
 *
 * Plus a TOC tree built from the frozen `DeepDiveCategory[]` contract owned
 * by Agent 3 (`lib/deep-dive.ts`). The tree:
 *   - filters live as the user types / toggles chips
 *   - shows finding-count + rule-count badges per node
 *   - shows a single most-severe-finding dot per sub-category
 *   - reflects the IO-active section via aria-current="location"
 *
 * The sidebar is a *navigation* component — it never renders findings
 * itself. The long-scroll content is owned by Agent 4. Ids match the
 * frozen contract: `cat-<id>` for categories, `sub-<id>` for sub-categories.
 *
 * URL state (frozen — Agent 6 verifies this in regression test):
 *   ?q=<search>            search term (debounced 250ms)
 *   ?sev=critical,high     severities to include (default = all)
 *   ?fw=eu_ai_act,...      frameworks to include (default = all)
 *   ?fail_only=1           hide passed rules
 *   ?show_skipped=1        include skipped rules
 *
 * Design lessons honoured:
 *   - Cluster B m2: only declared CSS tokens are referenced (--text not --text-1).
 *   - Cluster C M1: this is a CLIENT component and does not interpose between
 *     RSC and its data — Agent 3's <DeepDiveLayout/> performs the deep-dive
 *     fetch on the server side and threads `categories` in as a prop. We do
 *     NOT fetch here.
 */

import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { useRouter, useSearchParams, usePathname } from "next/navigation";
import type {
  DeepDiveCategory,
  DeepDiveSeverity,
  DeepDiveSubCategory,
  DeepDiveRule,
} from "@/lib/deep-dive";
import {
  FRAMEWORK_SHORT_LABELS,
  type FrameworkId,
} from "@/lib/framework-labels";

// ── Vocabulary maps ────────────────────────────────────────────────────────

const SEVERITIES: DeepDiveSeverity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "informational",
];

/**
 * Severity → short-label map (mirrors `framework-labels.ts` pattern). Display
 * only — never re-derives the canonical vocabulary.
 */
const SEVERITY_SHORT_LABELS: Record<DeepDiveSeverity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  informational: "Info",
};

/** Severity rank — most severe first. Used for "most-severe dot" computation. */
const SEVERITY_RANK: Record<DeepDiveSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  informational: 4,
};

const ALL_FRAMEWORK_IDS: FrameworkId[] = [
  "eu_ai_act",
  "iso_27001",
  "owasp_mcp",
  "owasp_asi",
  "cosai_mcp",
  "maestro",
  "mitre_atlas",
];

// Canonical ordering of framework chips — matches the matrix above on the page.
const FRAMEWORK_CHIP_ORDER: FrameworkId[] = ALL_FRAMEWORK_IDS;

// ── URL-state helpers (frozen schema) ─────────────────────────────────────

const URL_PARAM_SEARCH = "q";
const URL_PARAM_SEVERITY = "sev";
const URL_PARAM_FRAMEWORK = "fw";
const URL_PARAM_FAIL_ONLY = "fail_only";
const URL_PARAM_SHOW_SKIPPED = "show_skipped";

const DEBOUNCE_MS_SEARCH = 250;
const MOBILE_BREAKPOINT_PX = 720;

interface FilterState {
  search: string;
  severities: ReadonlySet<DeepDiveSeverity>;
  frameworks: ReadonlySet<FrameworkId>;
  failOnly: boolean;
  showSkipped: boolean;
}

function readFilterState(params: URLSearchParams): FilterState {
  const q = params.get(URL_PARAM_SEARCH) ?? "";

  const sevRaw = params.get(URL_PARAM_SEVERITY);
  const severities: Set<DeepDiveSeverity> = sevRaw
    ? new Set(
        sevRaw
          .split(",")
          .map((s) => s.trim().toLowerCase())
          .filter((s): s is DeepDiveSeverity =>
            (SEVERITIES as string[]).includes(s),
          ),
      )
    : new Set(SEVERITIES);

  // Empty after filtering = "all selected" rather than "nothing selected".
  // Prevents a stale URL from accidentally hiding every rule.
  const finalSeverities = severities.size === 0 ? new Set(SEVERITIES) : severities;

  const fwRaw = params.get(URL_PARAM_FRAMEWORK);
  const frameworks: Set<FrameworkId> = fwRaw
    ? new Set(
        fwRaw
          .split(",")
          .map((s) => s.trim().toLowerCase())
          .filter((s): s is FrameworkId =>
            (ALL_FRAMEWORK_IDS as string[]).includes(s),
          ),
      )
    : new Set(ALL_FRAMEWORK_IDS);
  const finalFrameworks =
    frameworks.size === 0 ? new Set(ALL_FRAMEWORK_IDS) : frameworks;

  return {
    search: q,
    severities: finalSeverities,
    frameworks: finalFrameworks,
    failOnly: params.get(URL_PARAM_FAIL_ONLY) === "1",
    showSkipped: params.get(URL_PARAM_SHOW_SKIPPED) === "1",
  };
}

function writeFilterState(
  base: URLSearchParams,
  next: FilterState,
): URLSearchParams {
  const out = new URLSearchParams(base.toString());

  // search
  if (next.search.length > 0) {
    out.set(URL_PARAM_SEARCH, next.search);
  } else {
    out.delete(URL_PARAM_SEARCH);
  }

  // severity — only persisted when not "all"
  if (next.severities.size > 0 && next.severities.size < SEVERITIES.length) {
    out.set(
      URL_PARAM_SEVERITY,
      SEVERITIES.filter((s) => next.severities.has(s)).join(","),
    );
  } else {
    out.delete(URL_PARAM_SEVERITY);
  }

  // framework — only persisted when not "all"
  if (
    next.frameworks.size > 0 &&
    next.frameworks.size < ALL_FRAMEWORK_IDS.length
  ) {
    out.set(
      URL_PARAM_FRAMEWORK,
      ALL_FRAMEWORK_IDS.filter((f) => next.frameworks.has(f)).join(","),
    );
  } else {
    out.delete(URL_PARAM_FRAMEWORK);
  }

  if (next.failOnly) out.set(URL_PARAM_FAIL_ONLY, "1");
  else out.delete(URL_PARAM_FAIL_ONLY);

  if (next.showSkipped) out.set(URL_PARAM_SHOW_SKIPPED, "1");
  else out.delete(URL_PARAM_SHOW_SKIPPED);

  return out;
}

// ── Search index ──────────────────────────────────────────────────────────

interface SearchToken {
  ruleId: string;
  ruleName: string;
  ruleSummary: string;
  subCategoryTitle: string;
  categoryTitle: string;
  haystack: string; // Pre-normalised concat used by fuzzy match.
  ruleSeverity: DeepDiveSeverity;
  ruleStatus: DeepDiveRule["status"];
  ruleFrameworkIds: ReadonlySet<FrameworkId>;
  categoryId: string;
  subCategoryId: string;
}

/** Normalise to lower-case ASCII alphanumerics — spaces and punctuation dropped. */
export function normaliseForSearch(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "");
}

function buildSearchIndex(categories: DeepDiveCategory[]): SearchToken[] {
  const tokens: SearchToken[] = [];
  for (const cat of categories) {
    for (const sub of cat.sub_categories) {
      for (const rule of sub.rules) {
        const fwSet = new Set<FrameworkId>(
          rule.framework_controls
            .map((fc) => fc.framework as FrameworkId)
            .filter((id): id is FrameworkId =>
              (ALL_FRAMEWORK_IDS as string[]).includes(id),
            ),
        );
        const haystack = normaliseForSearch(
          [
            rule.rule_id,
            rule.name,
            rule.summary,
            sub.title,
            cat.title,
          ].join(" "),
        );
        tokens.push({
          ruleId: rule.rule_id,
          ruleName: rule.name,
          ruleSummary: rule.summary,
          subCategoryTitle: sub.title,
          categoryTitle: cat.title,
          haystack,
          ruleSeverity: rule.severity,
          ruleStatus: rule.status,
          ruleFrameworkIds: fwSet,
          categoryId: cat.id,
          subCategoryId: sub.id,
        });
      }
    }
  }
  return tokens;
}

/**
 * Decide whether a single rule passes the active filter set.
 *
 * Order of checks: cheapest first (boolean toggles), then set membership,
 * then string match. Pulled out as a free function so the test suite can
 * exercise predicate behaviour in isolation.
 */
export function ruleMatchesFilter(
  token: SearchToken,
  filter: FilterState,
  normalisedQuery: string,
): boolean {
  // "only failing" — must have status === "findings"
  if (filter.failOnly && token.ruleStatus !== "findings") return false;

  // "include skipped" — when OFF, hide skipped rules
  if (!filter.showSkipped && token.ruleStatus === "skipped") return false;

  // severity multi-select
  if (!filter.severities.has(token.ruleSeverity)) return false;

  // framework multi-select — pass if either:
  //   (a) no framework_controls on the rule (rule has no cross-walk), OR
  //   (b) at least one of its frameworks is in the selected set.
  // Rationale: framework filter narrows the *cross-walk view*; a rule with no
  // cross-walk should never disappear because a framework was unticked.
  if (token.ruleFrameworkIds.size > 0) {
    let any = false;
    for (const f of token.ruleFrameworkIds) {
      if (filter.frameworks.has(f)) {
        any = true;
        break;
      }
    }
    if (!any) return false;
  }

  // search — substring on the normalised haystack
  if (normalisedQuery.length > 0 && !token.haystack.includes(normalisedQuery)) {
    return false;
  }

  return true;
}

// ── Aggregation helpers ───────────────────────────────────────────────────

interface SubCategorySummary {
  id: string;
  title: string;
  findingCount: number;
  ruleCount: number;
  matched: boolean;
  mostSevere: DeepDiveSeverity | null;
}

interface CategorySummary {
  id: string;
  title: string;
  findingCount: number;
  ruleCount: number;
  matched: boolean;
  subs: SubCategorySummary[];
}

function buildSummaries(
  categories: DeepDiveCategory[],
  matchedIds: ReadonlySet<string>,
  filter: FilterState,
  normalisedQuery: string,
): CategorySummary[] {
  return categories.map((cat) => {
    let catFindingCount = 0;
    let catRuleCount = 0;
    let catMatched = false;
    const subs: SubCategorySummary[] = cat.sub_categories.map((sub) => {
      // Per-sub aggregates — counts use the *full* rule set on the sub and
      // mask out rules that don't pass `failOnly`/`showSkipped` (so the badge
      // shows what is actually visible). They do NOT mask by severity/framework
      // because those are user-driven view filters, not "rule existence"
      // signals — the regulator wants to know how big a sub-category is, not
      // whether they happen to have a chip selected.
      let findingCount = 0;
      let ruleCount = 0;
      let mostSevere: DeepDiveSeverity | null = null;
      let subMatched = false;
      for (const rule of sub.rules) {
        if (filter.failOnly && rule.status !== "findings") continue;
        if (!filter.showSkipped && rule.status === "skipped") continue;
        ruleCount += 1;
        findingCount += rule.findings.length;
        for (const f of rule.findings) {
          if (
            mostSevere == null ||
            SEVERITY_RANK[f.severity] < SEVERITY_RANK[mostSevere]
          ) {
            mostSevere = f.severity;
          }
        }
        const tokenKey = `${cat.id}::${sub.id}::${rule.rule_id}`;
        if (matchedIds.has(tokenKey)) subMatched = true;
      }
      // If the search box is empty AND no severity/framework filter is
      // narrowing, every sub with at least one rule counts as "matched".
      if (
        normalisedQuery.length === 0 &&
        filter.severities.size === SEVERITIES.length &&
        filter.frameworks.size === ALL_FRAMEWORK_IDS.length
      ) {
        subMatched = ruleCount > 0;
      }

      catFindingCount += findingCount;
      catRuleCount += ruleCount;
      if (subMatched) catMatched = true;

      return {
        id: sub.id,
        title: sub.title,
        findingCount,
        ruleCount,
        matched: subMatched,
        mostSevere,
      };
    });

    return {
      id: cat.id,
      title: cat.title,
      findingCount: catFindingCount,
      ruleCount: catRuleCount,
      matched: catMatched,
      subs,
    };
  });
}

// ── Component ─────────────────────────────────────────────────────────────

export interface DeepDiveSidebarProps {
  categories: DeepDiveCategory[];
}

/** Test seam — non-default export for the unit suite. */
export { buildSearchIndex as __TEST_buildSearchIndex };
export { buildSummaries as __TEST_buildSummaries };
export { readFilterState as __TEST_readFilterState };
export { writeFilterState as __TEST_writeFilterState };

export default function DeepDiveSidebar({ categories }: DeepDiveSidebarProps) {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  // ── Build the search index once. Re-derive only when the categories
  //    themselves change — incoming RSC props are stable per render. ─────
  const index = useMemo(() => buildSearchIndex(categories), [categories]);

  // ── Hydrate filter state from the URL on first render. ────────────────
  const [filter, setFilter] = useState<FilterState>(() =>
    readFilterState(new URLSearchParams(searchParams?.toString() ?? "")),
  );

  // Local search input — separate from `filter.search` so the URL writeback
  // can debounce without the input lagging.
  const [searchInput, setSearchInput] = useState<string>(filter.search);

  // Track active scroll-spy anchor (cat-* / sub-*).
  const [activeAnchor, setActiveAnchor] = useState<string | null>(null);

  // ── URL writeback ─────────────────────────────────────────────────────
  const writeUrl = useCallback(
    (next: FilterState) => {
      const base = new URLSearchParams(searchParams?.toString() ?? "");
      const merged = writeFilterState(base, next);
      const qs = merged.toString();
      const target = pathname + (qs ? `?${qs}` : "");
      router.push(target, { scroll: false });
    },
    [pathname, router, searchParams],
  );

  // Debounced search writeback
  useEffect(() => {
    const handle = setTimeout(() => {
      if (searchInput !== filter.search) {
        const next: FilterState = { ...filter, search: searchInput };
        setFilter(next);
        writeUrl(next);
      }
    }, DEBOUNCE_MS_SEARCH);
    return () => clearTimeout(handle);
  }, [searchInput, filter, writeUrl]);

  // ── Filter mutations (chips/toggles — no debounce) ────────────────────
  const toggleSeverity = useCallback(
    (sev: DeepDiveSeverity) => {
      setFilter((prev) => {
        const nextSet = new Set(prev.severities);
        if (nextSet.has(sev)) nextSet.delete(sev);
        else nextSet.add(sev);
        const next = { ...prev, severities: nextSet };
        writeUrl(next);
        return next;
      });
    },
    [writeUrl],
  );

  const toggleFramework = useCallback(
    (fw: FrameworkId) => {
      setFilter((prev) => {
        const nextSet = new Set(prev.frameworks);
        if (nextSet.has(fw)) nextSet.delete(fw);
        else nextSet.add(fw);
        const next = { ...prev, frameworks: nextSet };
        writeUrl(next);
        return next;
      });
    },
    [writeUrl],
  );

  const toggleFailOnly = useCallback(() => {
    setFilter((prev) => {
      const next = { ...prev, failOnly: !prev.failOnly };
      writeUrl(next);
      return next;
    });
  }, [writeUrl]);

  const toggleShowSkipped = useCallback(() => {
    setFilter((prev) => {
      const next = { ...prev, showSkipped: !prev.showSkipped };
      writeUrl(next);
      return next;
    });
  }, [writeUrl]);

  // Search input keyboard handlers
  const onSearchKeyDown = useCallback(
    (ev: React.KeyboardEvent<HTMLInputElement>) => {
      if (ev.key === "Escape") {
        ev.preventDefault();
        setSearchInput("");
      }
    },
    [],
  );

  // ── Compute matched rule keys + summaries ─────────────────────────────
  const normalisedQuery = useMemo(
    () => normaliseForSearch(filter.search),
    [filter.search],
  );

  const matchedIds = useMemo(() => {
    const out = new Set<string>();
    for (const tok of index) {
      if (ruleMatchesFilter(tok, filter, normalisedQuery)) {
        out.add(`${tok.categoryId}::${tok.subCategoryId}::${tok.ruleId}`);
      }
    }
    return out;
  }, [index, filter, normalisedQuery]);

  const summaries = useMemo(
    () => buildSummaries(categories, matchedIds, filter, normalisedQuery),
    [categories, matchedIds, filter, normalisedQuery],
  );

  // ── Scroll-spy via IntersectionObserver ───────────────────────────────
  // We re-run the observer every time the visible TOC node-set changes —
  // categories that were filtered out lose their spy contribution.
  useEffect(() => {
    if (typeof window === "undefined") return;
    if (typeof IntersectionObserver === "undefined") return;

    const visibleIds: string[] = [];
    for (const cat of summaries) {
      if (cat.matched) visibleIds.push(`cat-${cat.id}`);
      for (const sub of cat.subs) {
        if (sub.matched) visibleIds.push(`sub-${sub.id}`);
      }
    }

    const elements: Element[] = [];
    for (const id of visibleIds) {
      const el = document.getElementById(id);
      if (el) elements.push(el);
    }
    if (elements.length === 0) {
      setActiveAnchor(null);
      return;
    }

    // Map element → its last intersectionRatio so we can pick the most-visible.
    const visibility = new Map<Element, number>();

    const observer = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          visibility.set(e.target, e.isIntersecting ? e.intersectionRatio : 0);
        }
        // Pick the element nearest the top of the viewport that is
        // intersecting at all — falling back to the most-recent intersection.
        let bestId: string | null = null;
        let bestTop = Number.POSITIVE_INFINITY;
        for (const [el, ratio] of visibility) {
          if (ratio <= 0) continue;
          const rect = el.getBoundingClientRect();
          if (rect.top < bestTop) {
            bestTop = rect.top;
            bestId = el.id;
          }
        }
        setActiveAnchor(bestId);
      },
      {
        // 30%-from-top sweet spot — fires before the heading scrolls past
        // the sticky rail header, after it has cleared the page chrome.
        rootMargin: "-20% 0px -65% 0px",
        threshold: [0, 0.25, 0.5, 0.75, 1],
      },
    );

    for (const el of elements) {
      observer.observe(el);
    }

    return () => {
      observer.disconnect();
    };
  }, [summaries]);

  // ── Mobile collapse — `<details>` accordion ─────────────────────────
  // We don't try to detect mobile in JS — the browser handles it via CSS
  // container queries on the parent. We *do* persist the open state to
  // localStorage on best-effort so the user can reopen mid-session.
  const detailsRef = useRef<HTMLDetailsElement | null>(null);
  useEffect(() => {
    if (typeof window === "undefined") return;
    const node = detailsRef.current;
    if (!node) return;
    try {
      const saved = window.localStorage.getItem("dds:open");
      if (saved === "1") node.open = true;
    } catch {
      /* storage may be disabled — best-effort only */
    }
    const onToggle = () => {
      try {
        window.localStorage.setItem("dds:open", node.open ? "1" : "0");
      } catch {
        /* no-op */
      }
    };
    node.addEventListener("toggle", onToggle);
    return () => node.removeEventListener("toggle", onToggle);
  }, []);

  // ── Filter chips (severity + framework) ──────────────────────────────
  const severityChips = SEVERITIES.map((sev) => {
    const active = filter.severities.has(sev);
    return (
      <button
        key={sev}
        type="button"
        className={`ddf-chip ddf-sev-chip${active ? " ddf-chip-active" : ""}`}
        aria-pressed={active}
        onClick={() => toggleSeverity(sev)}
      >
        <span
          className="ddf-chip-dot"
          style={{ background: `var(--sev-${sev === "informational" ? "info" : sev})` }}
          aria-hidden="true"
        />
        {SEVERITY_SHORT_LABELS[sev]}
      </button>
    );
  });

  const frameworkChips = FRAMEWORK_CHIP_ORDER.map((fw) => {
    const active = filter.frameworks.has(fw);
    return (
      <button
        key={fw}
        type="button"
        className={`ddf-chip ddf-fw-chip${active ? " ddf-chip-active" : ""}`}
        aria-pressed={active}
        onClick={() => toggleFramework(fw)}
      >
        {FRAMEWORK_SHORT_LABELS[fw]}
      </button>
    );
  });

  // ── TOC tree ─────────────────────────────────────────────────────────
  const tree = (
    <ul className="ddt-tree" role="tree" aria-label="Deep dive categories">
      {summaries.map((cat) => {
        const catAnchor = `cat-${cat.id}`;
        const catActive = activeAnchor === catAnchor;
        const catMuted = !cat.matched;
        return (
          <li
            key={cat.id}
            className={`ddt-cat${catMuted ? " ddt-cat-muted" : ""}${catActive ? " ddt-cat-active" : ""}`}
            role="treeitem"
            aria-expanded={cat.matched}
            aria-current={catActive ? "location" : undefined}
          >
            <a
              className="ddt-cat-link"
              href={`#${catAnchor}`}
              data-anchor={catAnchor}
            >
              <span className="ddt-cat-title">{cat.title}</span>
              <span className="ddt-count">
                <span className="ddt-count-findings">({cat.findingCount})</span>
                {!filter.failOnly && (
                  <span className="ddt-count-rules">
                    {" · "}
                    {cat.ruleCount} rules
                  </span>
                )}
              </span>
            </a>
            {cat.matched && cat.subs.length > 0 && (
              <ul className="ddt-sub-list" role="group">
                {cat.subs.map((sub) => {
                  const subAnchor = `sub-${sub.id}`;
                  const subActive = activeAnchor === subAnchor;
                  const subMuted = !sub.matched;
                  return (
                    <li
                      key={sub.id}
                      className={`ddt-sub${subMuted ? " ddt-sub-muted" : ""}${subActive ? " ddt-sub-active" : ""}`}
                      role="treeitem"
                      aria-current={subActive ? "location" : undefined}
                    >
                      <a
                        className="ddt-sub-link"
                        href={`#${subAnchor}`}
                        data-anchor={subAnchor}
                      >
                        <span className="ddt-sub-title">{sub.title}</span>
                        <span className="ddt-count">
                          <span className="ddt-count-findings">({sub.findingCount})</span>
                          {!filter.failOnly && (
                            <span className="ddt-count-rules">
                              {" · "}
                              {sub.ruleCount} rules
                            </span>
                          )}
                          {sub.mostSevere && (
                            <span
                              className={`ddt-sev-dot ddt-sev-${
                                sub.mostSevere === "informational"
                                  ? "info"
                                  : sub.mostSevere
                              }`}
                              aria-label={`most severe: ${sub.mostSevere}`}
                            />
                          )}
                        </span>
                      </a>
                    </li>
                  );
                })}
              </ul>
            )}
          </li>
        );
      })}
    </ul>
  );

  // ── Body — search + filters + tree ──────────────────────────────────
  const body = (
    <div className="dds-body">
      <div className="dds-search-row">
        <input
          type="search"
          className="dds-search"
          placeholder="Filter rules…"
          aria-label="Filter rules"
          value={searchInput}
          onChange={(e) => setSearchInput(e.target.value)}
          onKeyDown={onSearchKeyDown}
        />
      </div>

      <div className="ddf-row" role="group" aria-label="Filter by severity">
        {severityChips}
      </div>

      <div className="ddf-row" role="group" aria-label="Filter by framework">
        {frameworkChips}
      </div>

      <div className="ddf-toggles" role="group" aria-label="Result toggles">
        <button
          type="button"
          className={`ddf-toggle${filter.failOnly ? " ddf-toggle-active" : ""}`}
          aria-pressed={filter.failOnly}
          onClick={toggleFailOnly}
        >
          <span className="ddf-toggle-mark" aria-hidden="true">
            {filter.failOnly ? "✓" : ""}
          </span>
          only failing rules
        </button>
        <button
          type="button"
          className={`ddf-toggle${filter.showSkipped ? " ddf-toggle-active" : ""}`}
          aria-pressed={filter.showSkipped}
          onClick={toggleShowSkipped}
        >
          <span className="ddf-toggle-mark" aria-hidden="true">
            {filter.showSkipped ? "✓" : ""}
          </span>
          include skipped
        </button>
      </div>

      <div className="ddt-wrap">{tree}</div>
    </div>
  );

  return (
    <nav
      className="dds-rail"
      aria-label="Deep dive table of contents"
      data-dds-mobile-bp={MOBILE_BREAKPOINT_PX}
    >
      {/* Desktop layout — always visible */}
      <div className="dds-desktop">{body}</div>

      {/* Mobile layout — <details> accordion */}
      <details className="dds-mobile" ref={detailsRef}>
        <summary className="dds-mobile-summary">
          Filter & navigate ({summaries.reduce((n, c) => n + c.findingCount, 0)} findings)
        </summary>
        {body}
      </details>
    </nav>
  );
}
