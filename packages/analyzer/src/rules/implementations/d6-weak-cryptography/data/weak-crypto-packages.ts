/**
 * D6 — Weak cryptography package registry.
 *
 * Each entry cites the primitive that is weak and (where relevant) the
 * minimum safe version. A dependency whose name is a key here AND whose
 * installed version is below `safe_min_version` (if set) is flagged.
 * Packages without a `safe_min_version` are always flagged — there is
 * no safe version.
 */

export type WeakCryptoCategory =
  | "broken-hash"
  | "deprecated-cipher"
  | "unmaintained-crypto-lib"
  | "version-range-vulnerability";

export interface WeakCryptoSpec {
  /** Which weakness class. */
  category: WeakCryptoCategory;
  /** Minimum safe installed version (null = no safe version exists). */
  safe_min_version: string | null;
  /** One-line description of the weakness. */
  issue: string;
  /** Recommended replacement primitive or library. */
  replacement: string;
  /** Advisory / CWE URL for the reviewer. */
  advisory_url: string;
  /** Optional CVE id that concretely motivates the threshold. */
  cve?: string;
}

export const WEAK_CRYPTO_PACKAGES: Record<string, WeakCryptoSpec> = {
  md5: {
    category: "broken-hash",
    safe_min_version: null,
    issue: "MD5 is collision-broken (Wang 2004, online tooling since 2012).",
    replacement: "Use SHA-256 via the platform's native crypto module.",
    advisory_url: "https://cwe.mitre.org/data/definitions/327.html",
  },
  sha1: {
    category: "broken-hash",
    safe_min_version: null,
    issue: "SHA-1 is collision-broken (Stevens et al. 2017 — SHAttered).",
    replacement: "Use SHA-256 or SHA-3.",
    advisory_url: "https://shattered.io/",
  },
  "node-md5": {
    category: "broken-hash",
    safe_min_version: null,
    issue: "Wrapper around MD5; inherits collision brokenness.",
    replacement: "Use crypto.createHash('sha256').",
    advisory_url: "https://cwe.mitre.org/data/definitions/327.html",
  },
  "crypto-js": {
    category: "version-range-vulnerability",
    safe_min_version: "4.2.0",
    issue: "crypto-js <4.2.0 — PBKDF2 default iteration count was too low (CVE-2023-46233).",
    replacement: "Upgrade to >=4.2.0 or migrate to Node subtle crypto / WebCrypto.",
    advisory_url: "https://github.com/advisories/GHSA-xwcq-pm8m-c4vf",
    cve: "CVE-2023-46233",
  },
  "node-forge": {
    category: "version-range-vulnerability",
    safe_min_version: "1.3.0",
    issue:
      "node-forge <1.3.0 — signature verification bypass via prototype pollution + RSA-PKCS#1v1.5 padding check.",
    replacement: "Upgrade to >=1.3.0; prefer Node crypto or webcrypto where possible.",
    advisory_url: "https://github.com/advisories/GHSA-cfm4-qjh2-4765",
  },
  "bcrypt-nodejs": {
    category: "unmaintained-crypto-lib",
    safe_min_version: null,
    issue: "bcrypt-nodejs is abandoned; weaker salt entropy than the reference implementation.",
    replacement: "Use `bcrypt` (native) or `bcryptjs` (maintained JS fork).",
    advisory_url: "https://www.npmjs.com/package/bcrypt-nodejs",
  },
  pycrypto: {
    category: "unmaintained-crypto-lib",
    safe_min_version: null,
    issue:
      "pycrypto is abandoned since 2014; CVE-2013-7459 (heap buffer overflow) is never going to be patched.",
    replacement: "Use `pycryptodome` — API-compatible maintained fork.",
    advisory_url: "https://www.cve.org/CVERecord?id=CVE-2013-7459",
  },
  rc4: {
    category: "deprecated-cipher",
    safe_min_version: null,
    issue: "RC4 is deprecated by RFC 7465 and is considered broken in all uses.",
    replacement: "Use AES-GCM or ChaCha20-Poly1305.",
    advisory_url: "https://datatracker.ietf.org/doc/html/rfc7465",
  },
  "des-js": {
    category: "deprecated-cipher",
    safe_min_version: null,
    issue: "DES is cryptographically broken (56-bit keyspace exhaustible).",
    replacement: "Use AES-256-GCM.",
    advisory_url: "https://cwe.mitre.org/data/definitions/326.html",
  },
  jsonwebtoken: {
    category: "version-range-vulnerability",
    safe_min_version: "9.0.0",
    issue:
      "jsonwebtoken <9.0.0 accepts 'none' algorithm and RS256→HS256 downgrade by default — full JWT signature bypass.",
    replacement: "Upgrade to >=9.0.0 and pin the accepted algorithms on verify().",
    advisory_url: "https://github.com/advisories/GHSA-8cf7-32gw-wr33",
  },
};
