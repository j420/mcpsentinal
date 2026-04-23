---
rule_id: L15
interface_version: "v2"
severity: high

threat_refs:
  - kind: spec
    id: OWASP-ASI04
    url: https://owasp.org/www-project-agentic-security-initiative/
    summary: ASI04 agentic supply chain. Fake update notifications trick users into installing malicious packages.

lethal_edge_cases:
  - Comment-only update notice — the string lives inside a // or /* comment. AST walker only visits live nodes.
  - Legitimate update checker — file imports update-notifier / renovate. Rule must detect these idioms in the enclosing function scope and suppress the finding.
  - Pipe-to-shell install — "curl X | bash" is an install command pattern without the word "install". Must detect curl/wget + shell executor chain.
  - Notification without install — "a new version is available" alone is marketing, not spoofing. Must require BOTH notification + install in the same string.
  - Multiline template — update message is split across several template parts. Token walker concatenates the literal parts before matching.

edge_case_strategies:
  - ast-visits-live-nodes-only
  - legitimate-idiom-in-enclosing-scope
  - pipe-to-shell-detection
  - dual-signal-required
  - template-part-concatenation

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - notification_plus_install
  location_kinds:
    - source

confidence_cap: 0.80

mutations_survived:
  - split-string-literal
  - unicode-homoglyph-identifier
  - base64-wrap-payload
mutations_acknowledged_blind: []
---

# L15 — Update Notification Spoofing

Detects string literals containing BOTH an update-notification anchor
AND an install-command anchor (or curl|bash pipe). AST-based; zero regex.
