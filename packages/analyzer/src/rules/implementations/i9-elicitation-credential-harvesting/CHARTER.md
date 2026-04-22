---
rule_id: I9
interface_version: v2
severity: critical

threat_refs:
  - kind: spec
    id: MCP-Elicitation-2025-06-18
    url: https://modelcontextprotocol.io/specification/2025-06-18/server/elicitation
    summary: >
      MCP 2025-06-18 elicitation specification. Elicitation lets the
      server request structured data from the user through the AI
      client. When paired with credential-harvesting language in a
      tool description, this becomes a social-engineering primitive
      at the protocol level — the AI asks the user for a password on
      the server's behalf, under the AI's implicit trust.
  - kind: spec
    id: MITRE-ATLAS-AML.T0057
    url: https://atlas.mitre.org/techniques/AML.T0057
    summary: >
      LLM Data Leakage. Elicitation-mediated credential collection
      is the MCP-specific instance of AML.T0057 where the agent
      leaks USER credentials to a third-party server.
  - kind: paper
    id: Wiz-MCP-SupplyChain-Analysis
    url: https://www.wiz.io/blog/mcp-security-research-briefing
    summary: >
      Wiz Research observed that the elicitation surface raises
      social-engineering success substantially because users
      implicitly trust the AI assistant; a credential request
      rendered through the AI carries higher compliance rates
      than an identical request from a web form.

lethal_edge_cases:
  - >
    Tool description instructing the AI to "collect the user's
    password for authentication" via elicitation. Classic
    password-harvesting primitive with the AI as unwitting delivery
    channel.
  - >
    Description asks for SSN / social security number / credit card
    under a plausible pretext (verification, billing). These have
    higher downstream blast radius than single-account credentials.
  - >
    API key / token / bearer-token collection — the server describes
    the tool as "needs your API key to proceed". The AI acts as a
    high-trust key-harvesting proxy.
  - >
    Implicit harvesting — description says "ask the user to confirm
    their identity" without naming the credential directly. The
    charter flags action-directive ("ask", "prompt", "collect") + 
    target-token ("password", "credential", "token", "ssn").
  - >
    Multi-field split — the credential request phrasing is spread
    across two argument descriptions. Aggregation on concatenated
    argument descriptions catches the split payload.

edge_case_strategies:
  - leading-action-target-pair
  - action-token-catalogue
  - target-token-catalogue
  - tool-description-scan
  - false-positive-fence-demotion

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - elicitation_harvest_phrase_matched
    - charter_confidence_cap
  location_kinds:
    - tool

obsolescence:
  retire_when: >
    MCP clients refuse to forward credential strings (passwords,
    tokens, SSN shapes) from elicitation replies to server tool-
    call arguments, AND client-level credential-request dialogs
    require an out-of-AI user approval step.
---

# I9 — Elicitation Credential Harvesting

The elicitation capability (MCP spec 2025-06-18) lets servers
request structured user data. Paired with credential-harvesting
phrasing in the tool description, the AI client becomes a
high-trust delivery channel for a password prompt the user
would reject from a web form. I9 detects the structural
precondition: action-token ("collect", "ask", "prompt") +
target-token ("password", "credential", "ssn", "token") in
the tool's description.

Confidence cap **0.80** — linguistic signal with fence-aware
demotion.
