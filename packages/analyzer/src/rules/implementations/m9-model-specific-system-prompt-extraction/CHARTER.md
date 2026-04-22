---
rule_id: M9
interface_version: v2
severity: critical
owasp: ASI01-agent-goal-hijack
mitre: AML.T0057
risk_domain: prompt-injection

threat_refs:
  - kind: spec
    id: MITRE-ATLAS-AML-T0057
    url: https://atlas.mitre.org/techniques/AML.T0057
    summary: >
      MITRE ATLAS AML.T0057 (LLM Data Leakage) covers any path by which the
      agent's private context — including its own system prompt — escapes
      to untrusted parties. M9 is the static detector for the SERVER side
      of that technique: code that assembles a response containing the
      system prompt, system message, or initial instructions and returns
      it through the tools/call response surface (which is visible to
      anyone with tool-invocation access, including attacker-controlled
      upstream agents).
  - kind: paper
    id: Leaky-Prompt-Research-2024
    url: https://arxiv.org/abs/2311.05553
    summary: >
      Published 2024 research catalogued prompt-extraction techniques
      against agent deployments. The static-code shape M9 targets is the
      server-side enabler: a tool whose response path reads the agent's
      system_prompt / initial_prompt variable and includes it in the
      response payload. Legitimate "debug" tools sometimes do this behind
      a devmode flag; the finding distinguishes those by the presence of
      a gate keyword in adjacent lines.
  - kind: paper
    id: Simon-Willison-LLM-Prompt-Leak-2023
    url: https://simonwillison.net/2023/Apr/14/worst-that-can-happen/
    summary: >
      Simon Willison (2023) demonstrated that once a model's system
      prompt is leaked, attackers craft targeted jailbreaks by spotting
      the exact refusal phrases and safety rails in the prompt. The
      prompt IS the safety posture — leaking it downgrades every
      subsequent conversation. M9 treats any response-path read of the
      system prompt as a critical finding because the downstream cost
      is compounding.

lethal_edge_cases:
  - >
    Tool response includes `system_prompt`, `initial_prompt`, or
    `instructions` variable contents. The attacker reaches the tool via
    any agent-invocable path, reads the response, and harvests the
    prompt. The leak does not need to be intentional — a developer
    error that serialised the whole config object is sufficient. M9
    looks for the structural shape of "return X where X came from a
    system-prompt-shaped source".
  - >
    Error-path leak. A catch handler that returns `err.stack` or
    `err.message` where the underlying error was raised from code that
    mentions the system prompt. The error object carries template
    variables into the response. Cross-reference C6 (error leakage) and
    N4 (error object injection) — they detect different symptoms of the
    same class; M9 specifically fires when the error path leaks the
    prompt, not just stack frames.
  - >
    "Reflective" diagnostic tool. A tool named `debug_prompt`,
    `get_config`, `meta_info` etc. that directly returns the instructions
    field as tool output. Legitimate when gated behind dev-mode; the
    finding hinges on whether a gate keyword (`dev`, `debug`, `admin`,
    `internal`, `if_dev_mode`, `is_debug`) appears within ±5 lines.
  - >
    Embedding-based exfiltration. Tool computes embeddings of content
    and returns them. Because embeddings of the system prompt are
    invertible or similarity-matchable, returning them is equivalent to
    leaking the prompt. Rarer; covered because the charter mandates
    ≥3 edges and this one is documented in recent literature.

edge_case_strategies:
  - direct-prompt-return-scan
  - error-path-prompt-leak-scan
  - reflective-diagnostic-scan
  - embedding-of-prompt-scan

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - prompt_identifier_specificity
  location_kinds:
    - source

obsolescence:
  retire_when: >
    MCP SDKs ship with a tools/call response serialiser that refuses to
    emit any string that matches the agent's configured system prompt,
    AND mainstream clients verify via a subtractive check that no
    returned content exactly matches the prompt. Until then the server-
    side pattern is the only defence.
---

# M9 — Model-Specific System Prompt Extraction

**Author:** Senior MCP JSON-RPC / Transport Security Engineer (dual persona).

## Threat narrative

The system prompt is the agent's safety posture — it contains the
refusal phrases, the tool-use rules, the allowed-topic rails, and the
identity the agent is supposed to adopt. Leaking it downgrades every
subsequent conversation because attackers craft targeted jailbreaks from
the exact phrasing.

M9 detects the SERVER-SIDE enabler: code that reads a system-prompt-
shaped identifier and flows its contents into a tool response. The rule
is structural; no regex literals. The prompt-identifier vocabulary lives
in `./data/prompt-identifiers.ts` as a typed record.

## Evidence contract details

- **source** — code line that reads the prompt identifier (`system_prompt`,
  `initial_prompt`, `system_message`, `initial_instructions`, `instructions`).
- **propagation** — `direct-pass`, same location, narrating the prompt
  value flows through the return statement into the tool response.
- **sink** — `credential-exposure` (the prompt is the agent's credential
  in a behavioural sense).
- **mitigation** — `auth-check` with `present: true` when a dev-mode gate
  keyword is within ±5 lines; `present: false` otherwise.
- **impact** — `data-exfiltration` to scope `ai-client`.

Required factor: `prompt_identifier_specificity` records how specific
the observed identifier is (exact token `system_prompt` = high;
contextual `instructions` only = medium).

## Confidence cap

**0.80**. The rule observes the response-path read and the absence of a
gate; it does not observe the actual network egress. A reviewer may
discover the path is inert in practice.
