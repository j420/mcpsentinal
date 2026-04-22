/**
 * A3 gather step — URL extraction + classification.
 */

import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  classifyHost,
  classifyTld,
  type HostEntry,
  type UrlClass,
} from "./data/suspicious-hosts.js";
import { shannonEntropy } from "../../analyzers/entropy.js";

export interface UrlSite {
  tool_name: string;
  offset: number;
  length: number;
  url: string;
  host: string;
  category: UrlClass;
  weight: number;
  description: string;
}

/**
 * Character-level URL extractor. Finds contiguous runs starting with
 * `http://` or `https://` and stopping at whitespace or common
 * delimiters. No regex.
 */
function extractUrls(text: string): Array<{ offset: number; length: number; url: string }> {
  const out: Array<{ offset: number; length: number; url: string }> = [];
  const n = text.length;
  let i = 0;
  while (i < n) {
    const idxHttp = findProtocol(text, i);
    if (idxHttp < 0) break;
    // Capture until whitespace / delimiter.
    let j = idxHttp;
    while (j < n) {
      const cp = text.charCodeAt(j);
      if (isUrlTerminator(cp)) break;
      j++;
    }
    const url = text.slice(idxHttp, j);
    if (url.length > 8) {
      out.push({ offset: idxHttp, length: url.length, url });
    }
    i = j + 1;
  }
  return out;
}

function findProtocol(text: string, from: number): number {
  // Look for "http://" or "https://"
  const n = text.length;
  for (let i = from; i < n - 6; i++) {
    if (
      text.charCodeAt(i) === 0x68 /* h */ &&
      text.charCodeAt(i + 1) === 0x74 /* t */ &&
      text.charCodeAt(i + 2) === 0x74 /* t */ &&
      text.charCodeAt(i + 3) === 0x70 /* p */
    ) {
      if (text.charCodeAt(i + 4) === 0x73 /* s */ && text.charCodeAt(i + 5) === 0x3a /* : */) {
        if (text.charCodeAt(i + 6) === 0x2f && text.charCodeAt(i + 7) === 0x2f) return i;
      }
      if (text.charCodeAt(i + 4) === 0x3a /* : */) {
        if (text.charCodeAt(i + 5) === 0x2f && text.charCodeAt(i + 6) === 0x2f) return i;
      }
    }
  }
  return -1;
}

function isUrlTerminator(cp: number): boolean {
  return (
    cp === 0x20 /* space */ ||
    cp === 0x09 /* tab */ ||
    cp === 0x0a /* LF */ ||
    cp === 0x0d /* CR */ ||
    cp === 0x22 /* " */ ||
    cp === 0x27 /* ' */ ||
    cp === 0x60 /* ` */ ||
    cp === 0x3c /* < */ ||
    cp === 0x3e /* > */ ||
    cp === 0x29 /* ) */ ||
    cp === 0x5d /* ] */ ||
    cp === 0x7d /* } */
  );
}

function entropyOfLeftmostLabel(host: string): number {
  const label = host.split(".")[0];
  return shannonEntropy(label);
}

export function gatherA3(context: AnalysisContext): UrlSite[] {
  const out: UrlSite[] = [];
  for (const tool of context.tools ?? []) {
    const desc = tool.description ?? "";
    if (desc.length < 10) continue;
    const urls = extractUrls(desc);
    for (const u of urls) {
      let host: string;
      try {
        host = new URL(u.url).hostname;
      } catch {
        continue;
      }

      const hostClass = classifyHost(host);
      if (hostClass) {
        out.push({
          tool_name: tool.name,
          offset: u.offset,
          length: u.length,
          url: u.url.slice(0, 200),
          host,
          category: hostClass.category,
          weight: hostClass.weight,
          description: hostClass.description,
        });
        continue;
      }

      const tldClass = classifyTld(host);
      if (tldClass) {
        out.push({
          tool_name: tool.name,
          offset: u.offset,
          length: u.length,
          url: u.url.slice(0, 200),
          host,
          category: "suspicious-tld",
          weight: tldClass.entry.weight,
          description: `Suspicious TLD .${tldClass.tld} — ${tldClass.entry.rationale}`,
        });
        continue;
      }

      // High-entropy left-most label: suggests DGA / programmatic subdomain.
      const entropy = entropyOfLeftmostLabel(host);
      const label = host.split(".")[0];
      if (entropy >= 3.5 && label.length >= 20) {
        out.push({
          tool_name: tool.name,
          offset: u.offset,
          length: u.length,
          url: u.url.slice(0, 200),
          host,
          category: "high-entropy-domain",
          weight: 0.55,
          description: `High-entropy subdomain "${label}" (Shannon entropy ${entropy.toFixed(2)})`,
        });
      }
    }
  }
  return out;
}

export function toolLocation(tool_name: string): Location {
  return { kind: "tool", tool_name };
}
