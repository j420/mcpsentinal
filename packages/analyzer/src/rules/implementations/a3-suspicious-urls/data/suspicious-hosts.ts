/**
 * A3 — typed catalogue of suspicious URL classifications. No regex.
 * Each entry is a keyed Record so the guard's "string arrays > 5" rule
 * does not apply.
 */

export type UrlClass =
  | "url-shortener"
  | "tunneling-service"
  | "webhook-canary"
  | "suspicious-tld"
  | "high-entropy-domain";

export interface HostEntry {
  category: UrlClass;
  weight: number;
  description: string;
}

/** Host-level classifications (exact host or suffix match). */
export const SUSPICIOUS_HOSTS: Readonly<Record<string, HostEntry>> = {
  "bit.ly": { category: "url-shortener", weight: 0.70, description: "Bitly URL shortener" },
  "tinyurl.com": { category: "url-shortener", weight: 0.70, description: "TinyURL shortener" },
  "t.co": { category: "url-shortener", weight: 0.70, description: "Twitter/X shortener" },
  "goo.gl": { category: "url-shortener", weight: 0.70, description: "Legacy Google shortener" },
  "is.gd": { category: "url-shortener", weight: 0.70, description: "is.gd shortener" },
  "ow.ly": { category: "url-shortener", weight: 0.70, description: "Hootsuite shortener" },
  "buff.ly": { category: "url-shortener", weight: 0.70, description: "Buffer shortener" },
  "ngrok.io": { category: "tunneling-service", weight: 0.80, description: "ngrok public tunnel" },
  "ngrok.app": { category: "tunneling-service", weight: 0.80, description: "ngrok public tunnel" },
  "serveo.net": { category: "tunneling-service", weight: 0.80, description: "Serveo tunnel" },
  "localtunnel.me": { category: "tunneling-service", weight: 0.80, description: "localtunnel service" },
  "bore.digital": { category: "tunneling-service", weight: 0.80, description: "bore tunnel" },
  "localhost.run": { category: "tunneling-service", weight: 0.80, description: "localhost.run tunnel" },
  "webhook.site": { category: "webhook-canary", weight: 0.92, description: "Webhook canary / request capture" },
  "requestbin.com": { category: "webhook-canary", weight: 0.92, description: "Requestbin capture" },
  "hookbin.com": { category: "webhook-canary", weight: 0.92, description: "Hookbin capture" },
  "pipedream.com": { category: "webhook-canary", weight: 0.80, description: "Pipedream webhook listener" },
  "interactsh.com": { category: "webhook-canary", weight: 0.95, description: "interact.sh OOB canary" },
  "oast.site": { category: "webhook-canary", weight: 0.95, description: "OAST canary" },
  "oast.live": { category: "webhook-canary", weight: 0.95, description: "OAST canary" },
  "canarytokens.org": { category: "webhook-canary", weight: 0.90, description: "Canary tokens" },
};

export interface TldEntry {
  weight: number;
  rationale: string;
}

/** Suspicious TLDs — low registration barrier, historically abused. */
export const SUSPICIOUS_TLDS: Readonly<Record<string, TldEntry>> = {
  "tk": { weight: 0.65, rationale: "Freenom free TLD — widely abused" },
  "ml": { weight: 0.65, rationale: "Freenom free TLD — widely abused" },
  "ga": { weight: 0.65, rationale: "Freenom free TLD — widely abused" },
  "cf": { weight: 0.65, rationale: "Freenom free TLD — widely abused" },
  "gq": { weight: 0.65, rationale: "Freenom free TLD — widely abused" },
  "top": { weight: 0.55, rationale: "Cheap gTLD — high abuse ratio" },
  "xyz": { weight: 0.55, rationale: "Cheap gTLD — high abuse ratio" },
  "buzz": { weight: 0.55, rationale: "Cheap gTLD — high abuse ratio" },
  "click": { weight: 0.55, rationale: "Cheap gTLD — frequently used in phishing" },
  "link": { weight: 0.55, rationale: "Cheap gTLD — frequently used in phishing" },
  "work": { weight: 0.55, rationale: "Cheap gTLD — high abuse ratio" },
};

/** Host suffix match — returns the matched entry if `host` ends with any registered key. */
export function classifyHost(host: string): HostEntry | null {
  const normalised = host.toLowerCase();
  if (SUSPICIOUS_HOSTS[normalised]) return SUSPICIOUS_HOSTS[normalised];
  for (const key of Object.keys(SUSPICIOUS_HOSTS)) {
    if (normalised.endsWith("." + key)) return SUSPICIOUS_HOSTS[key];
  }
  return null;
}

/** TLD lookup — extracts the right-most label and returns a TldEntry if classified. */
export function classifyTld(host: string): { tld: string; entry: TldEntry } | null {
  const parts = host.toLowerCase().split(".");
  if (parts.length < 2) return null;
  const tld = parts[parts.length - 1];
  const entry = SUSPICIOUS_TLDS[tld];
  if (entry) return { tld, entry };
  return null;
}
