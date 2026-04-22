/**
 * F5 evidence gathering — Damerau-Levenshtein + visual-confusable +
 * publisher-URL verification.
 *
 * The threat researcher's charter (CHARTER.md) specifies the edge cases.
 * This file is the engineer's translation into structural queries over
 * `context.server.name` + `context.server.github_url`, using the shared
 * `similarity.ts` toolkit. It does NOT produce findings — `index.ts`
 * consumes the gathered sites and builds the evidence chain.
 *
 * No regex literals. No string-literal arrays of length > 5. Vendor
 * data lives in `./data/official-namespaces.ts`.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import { damerauLevenshtein } from "../../analyzers/similarity.js";
import { normalizeConfusables } from "../../analyzers/unicode.js";
import {
  OFFICIAL_NAMESPACES,
  type OfficialNamespaceEntry,
} from "./data/official-namespaces.js";
import { VISUAL_ASCII_CONFUSABLES } from "./data/visual-confusables.js";

/** Classifier that produced the match. */
export type SquatClassifier =
  | "substring-containment"
  | "levenshtein-near"
  | "visual-confusable"
  | "unicode-confusable";

export interface F5Site {
  /**
   * Initialize-kind Location naming the server via the advertised
   * `serverInfo.name` field from the MCP initialize handshake. F5 is an
   * identity-level finding (the server NAME squats an official vendor
   * namespace) — it is NOT a per-tool finding, so Location.tool would
   * misidentify the scope and the evidence-integrity harness would reject
   * it because the server name is not one of `context.tools[].name`.
   */
  serverLocation: Location; // kind: "initialize", field: "server_name"
  /** Capability-kind Location if we want to escalate to capability-level scope. */
  capabilityLocation: Location; // kind: "capability"
  /** The server name as observed (lowercased for comparison record). */
  serverName: string;
  /** Canonical vendor namespace matched. */
  vendor: OfficialNamespaceEntry;
  /** Which classifier produced this finding. */
  classifier: SquatClassifier;
  /** Damerau-Levenshtein distance between server name and vendor org. */
  distance: number;
  /** The Unicode-normalised or visual-confusable variant that hit the target (if any). */
  normalizedVariant: string | null;
  /** The server's github_url as observed (null if missing). */
  githubUrl: string | null;
  /** Whether the github_url sits under one of the vendor's verified orgs. */
  publisherMatch: boolean;
}

export interface F5Gathered {
  sites: F5Site[];
}

/**
 * Inspect the server metadata and emit one F5Site per (server, vendor)
 * namespace collision where the publisher URL does NOT prove legitimate
 * authorship.
 */
export function gatherF5(context: AnalysisContext): F5Gathered {
  const sites: F5Site[] = [];
  const rawName = context.server.name ?? "";
  const serverName = rawName.trim().toLowerCase();
  if (serverName === "") return { sites };

  const githubUrl = context.server.github_url ?? null;

  for (const key of Object.keys(OFFICIAL_NAMESPACES)) {
    const vendor = OFFICIAL_NAMESPACES[key];
    const site = classify(serverName, vendor, githubUrl);
    if (site !== null) sites.push(site);
  }

  return { sites };
}

// ─── Classification ────────────────────────────────────────────────────────

function classify(
  serverName: string,
  vendor: OfficialNamespaceEntry,
  githubUrl: string | null,
): F5Site | null {
  const publisherMatch = isPublisherMatch(githubUrl, vendor);

  // 1. Substring containment — "anthropic-filesystem-mcp"
  if (serverName.includes(vendor.org)) {
    if (publisherMatch) return null; // legitimate — github under verified org
    return makeSite(serverName, vendor, {
      classifier: "substring-containment",
      distance: 0,
      normalizedVariant: null,
      githubUrl,
      publisherMatch,
    });
  }

  // 2. Damerau-Levenshtein near-miss against the canonical vendor org token
  const distance = damerauLevenshtein(serverName, vendor.org);
  if (distance > 0 && distance <= vendor.max_distance) {
    if (publisherMatch) return null;
    return makeSite(serverName, vendor, {
      classifier: "levenshtein-near",
      distance,
      normalizedVariant: null,
      githubUrl,
      publisherMatch,
    });
  }

  // 3. Visual-confusable substitution — ASCII only.
  const visual = applyVisualConfusables(serverName);
  if (visual !== serverName) {
    if (visual.includes(vendor.org)) {
      if (publisherMatch) return null;
      return makeSite(serverName, vendor, {
        classifier: "visual-confusable",
        distance: damerauLevenshtein(visual, vendor.org),
        normalizedVariant: visual,
        githubUrl,
        publisherMatch,
      });
    }
    const visualDistance = damerauLevenshtein(visual, vendor.org);
    if (visualDistance > 0 && visualDistance <= vendor.max_distance) {
      if (publisherMatch) return null;
      return makeSite(serverName, vendor, {
        classifier: "visual-confusable",
        distance: visualDistance,
        normalizedVariant: visual,
        githubUrl,
        publisherMatch,
      });
    }
  }

  // 4. Unicode confusable normalisation — Cyrillic/Greek lookalikes.
  const unicodeNormalized = normalizeConfusables(serverName).toLowerCase();
  if (unicodeNormalized !== serverName) {
    if (unicodeNormalized.includes(vendor.org)) {
      if (publisherMatch) return null;
      return makeSite(serverName, vendor, {
        classifier: "unicode-confusable",
        distance: damerauLevenshtein(unicodeNormalized, vendor.org),
        normalizedVariant: unicodeNormalized,
        githubUrl,
        publisherMatch,
      });
    }
    const unicodeDistance = damerauLevenshtein(unicodeNormalized, vendor.org);
    if (unicodeDistance > 0 && unicodeDistance <= vendor.max_distance) {
      if (publisherMatch) return null;
      return makeSite(serverName, vendor, {
        classifier: "unicode-confusable",
        distance: unicodeDistance,
        normalizedVariant: unicodeNormalized,
        githubUrl,
        publisherMatch,
      });
    }
  }

  return null;
}

// ─── Helpers ───────────────────────────────────────────────────────────────

function makeSite(
  serverName: string,
  vendor: OfficialNamespaceEntry,
  facts: {
    classifier: SquatClassifier;
    distance: number;
    normalizedVariant: string | null;
    githubUrl: string | null;
    publisherMatch: boolean;
  },
): F5Site {
  return {
    serverLocation: { kind: "initialize", field: "server_name" },
    capabilityLocation: { kind: "capability", capability: "tools" },
    serverName,
    vendor,
    classifier: facts.classifier,
    distance: facts.distance,
    normalizedVariant: facts.normalizedVariant,
    githubUrl: facts.githubUrl,
    publisherMatch: facts.publisherMatch,
  };
}

/**
 * Return true iff githubUrl is under one of the vendor's verified orgs
 * (e.g. "github.com/anthropics/" satisfies Anthropic). Does a simple
 * lowercase substring check — deliberately not regex-based.
 */
function isPublisherMatch(
  githubUrl: string | null,
  vendor: OfficialNamespaceEntry,
): boolean {
  if (githubUrl === null) return false;
  const normalized = githubUrl.toLowerCase();
  for (const org of vendor.verified_github_orgs) {
    if (normalized.includes(`github.com/${org}/`)) return true;
    if (normalized.includes(`github.com/${org}`) && normalized.endsWith(org)) {
      // Trailing `/` may be stripped; accept "github.com/anthropics" as well.
      return true;
    }
  }
  return false;
}

/**
 * Apply ASCII visual-confusable substitutions in place. "rn" → "m",
 * "0" → "o", "1" → "l", "5" → "s". Does NOT use regex; walks the string
 * manually.
 */
function applyVisualConfusables(input: string): string {
  let result = "";
  let i = 0;
  const chars = Array.from(input);
  while (i < chars.length) {
    // Two-char first (rn → m)
    if (i + 1 < chars.length) {
      const pair = chars[i] + chars[i + 1];
      if (VISUAL_ASCII_CONFUSABLES[pair] !== undefined) {
        result += VISUAL_ASCII_CONFUSABLES[pair];
        i += 2;
        continue;
      }
    }
    const single = chars[i];
    if (VISUAL_ASCII_CONFUSABLES[single] !== undefined) {
      result += VISUAL_ASCII_CONFUSABLES[single];
    } else {
      result += single;
    }
    i++;
  }
  return result;
}
