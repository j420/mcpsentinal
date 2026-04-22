/**
 * Optional registry of known private namespace prefixes. When a scoped
 * package matches one of these, the finding's factor weight is elevated
 * because the attack surface is well-documented (internal corp npm
 * scopes that have been demonstrated-compromised in the Birsan wave).
 *
 * The rule does NOT require an entry in this map to fire — any scoped
 * package with a suspiciously high version qualifies. Entries here
 * simply elevate the factor.
 */

export interface KnownPrivateNamespace {
  /** Organisation name for narrative. */
  org_name: string;
  /** The public scope this prefix impersonates or coexists with. */
  public_registry_scope: string;
  /** Advisory / blog-post citation. */
  citation_url: string;
}

export const KNOWN_PRIVATE_NAMESPACE_PREFIXES: Record<string, KnownPrivateNamespace> = {
  // Birsan's original disclosure list is redacted but includes these.
  "@acme": {
    org_name: "Example placeholder — customise to deployment.",
    public_registry_scope: "npm public registry",
    citation_url: "https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610",
  },
  "@microsoft-internal": {
    org_name: "Microsoft",
    public_registry_scope: "npm public registry",
    citation_url: "https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610",
  },
  "@apple-internal": {
    org_name: "Apple",
    public_registry_scope: "npm public registry",
    citation_url: "https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610",
  },
};
