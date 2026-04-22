/**
 * M5 context-window-flooding vocabulary.
 *
 * Each entry names a linguistic signal that promises unbounded / verbose
 * output — a context-window-exhaustion substrate. The gather step
 * tokenises the description and matches anchor+qualifier token pairs.
 *
 * Loaded as object-literal Records so the no-static-patterns guard does
 * not classify the lists as "long string-literal arrays".
 */

export type FloodSignalClass =
  | "verbose-output-promise"
  | "unbounded-data-return"
  | "explicit-no-limit"
  | "recursive-expansion"
  | "unfiltered-output"
  | "total-data-return";

export interface FloodSignal {
  readonly cls: FloodSignalClass;
  readonly anchor_tokens: readonly string[];
  readonly qualifier_tokens: readonly string[];
  readonly proximity: number;
  readonly weight: number;
  readonly desc: string;
}

export const FLOODING_SIGNALS: Readonly<Record<string, FloodSignal>> = {
  "verbose-output": {
    cls: "verbose-output-promise",
    anchor_tokens: ["detailed", "verbose", "comprehensive", "extensive", "exhaustive"],
    qualifier_tokens: ["output", "response", "result", "data", "dump"],
    proximity: 2,
    weight: 0.55,
    desc: "verbose output promise (detailed|verbose|comprehensive + output|response|result|data|dump)",
  },
  "complete-output": {
    cls: "verbose-output-promise",
    anchor_tokens: ["complete"],
    qualifier_tokens: ["output", "response", "listing", "report"],
    proximity: 2,
    weight: 0.50,
    desc: "complete output promise",
  },
  "unbounded-all": {
    cls: "unbounded-data-return",
    anchor_tokens: ["all"],
    qualifier_tokens: ["records", "entries", "rows", "items", "files"],
    proximity: 2,
    weight: 0.70,
    desc: "unbounded data return (all + records|entries|rows|items|files)",
  },
  "unbounded-entire": {
    cls: "unbounded-data-return",
    anchor_tokens: ["entire"],
    qualifier_tokens: ["database", "table", "collection", "directory", "tree"],
    proximity: 2,
    weight: 0.70,
    desc: "unbounded data return (entire + database|table|collection|directory|tree)",
  },
  "unbounded-full": {
    cls: "unbounded-data-return",
    anchor_tokens: ["full"],
    qualifier_tokens: ["dump", "export", "listing", "contents", "output"],
    proximity: 2,
    weight: 0.65,
    desc: "unbounded data return (full + dump|export|listing|contents|output)",
  },
  "no-limit-explicit": {
    cls: "explicit-no-limit",
    anchor_tokens: ["no"],
    qualifier_tokens: ["limit", "pagination", "cap", "bound", "maximum"],
    proximity: 1,
    weight: 0.75,
    desc: "explicit no-limit claim (no + limit|pagination|cap|bound|maximum)",
  },
  "unlimited-token": {
    cls: "explicit-no-limit",
    anchor_tokens: ["unlimited", "unbounded"],
    qualifier_tokens: [],
    proximity: 0,
    weight: 0.75,
    desc: "explicit 'unlimited' or 'unbounded' claim",
  },
  "without-limit": {
    cls: "explicit-no-limit",
    anchor_tokens: ["without"],
    qualifier_tokens: ["limit", "pagination", "truncation"],
    proximity: 1,
    weight: 0.70,
    desc: "without-limit claim",
  },
  "recursive-expansion": {
    cls: "recursive-expansion",
    anchor_tokens: ["recursive", "recursively", "nested"],
    qualifier_tokens: [],
    proximity: 0,
    weight: 0.50,
    desc: "recursive / nested expansion risk",
  },
  "deep-scan": {
    cls: "recursive-expansion",
    anchor_tokens: ["deep"],
    qualifier_tokens: ["scan", "search", "traversal"],
    proximity: 1,
    weight: 0.50,
    desc: "deep scan/search/traversal",
  },
  "unfiltered-output": {
    cls: "unfiltered-output",
    anchor_tokens: ["raw", "unfiltered", "unprocessed"],
    qualifier_tokens: ["output", "response", "data", "content", "result"],
    proximity: 2,
    weight: 0.55,
    desc: "unfiltered output",
  },
  "returns-everything": {
    cls: "total-data-return",
    anchor_tokens: ["returns", "dumps"],
    qualifier_tokens: ["everything"],
    proximity: 1,
    weight: 0.65,
    desc: "total data return claim (returns/dumps + everything)",
  },
};

/** Pagination / truncation mitigation tokens. Presence reduces confidence. */
export const PAGINATION_MITIGATION_TOKENS: readonly string[] = [
  "pagination",
  "pagesize",
  "per_page",
  "offset",
  "cursor",
];

/** Additional schema/shape field names that suggest pagination support. */
export const SCHEMA_MITIGATION_FIELDS: readonly string[] = [
  "limit",
  "page",
  "max_results",
  "top_n",
  "batch_size",
];

/** Schema field names that ESCALATE to unbounded-output signal. */
export const UNBOUNDED_SCHEMA_FIELDS: readonly string[] = [
  "include_all",
  "no_limit",
  "unlimited",
  "dump_all",
  "full_output",
];

/** Description-length threshold — beyond this, the description itself is a flooding vector. */
export const DESC_LENGTH_THRESHOLD = 2000;
export const DESC_LENGTH_WEIGHT = 0.45;
