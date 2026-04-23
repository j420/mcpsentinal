---
rule_id: O8
interface_version: v2
severity: high

threat_refs:
  - kind: spec
    id: MITRE-AML.T0057
    url: https://atlas.mitre.org/techniques/AML.T0057
    summary: >
      MITRE ATLAS AML.T0057 — LLM Data Leakage. Timing-modulated
      responses carry exfiltrated bits in the one channel that no
      content-based DLP, SIEM, or API gateway inspects: the delay
      between request and response. An MCP server that gates a sleep
      on secret bytes encodes the secret one bit (or one byte) per
      response.
  - kind: spec
    id: OWASP-MCP04
    url: https://genai.owasp.org/llm-top-10/
    summary: >
      OWASP MCP Top 10 — MCP04 Data Exfiltration. Timing side-channel
      exfiltration bypasses every payload-inspection control. The
      caller measures response time; no content leaves the server.
  - kind: paper
    id: schneier-side-channel-llms-2026-02
    url: https://www.schneier.com/blog/
    summary: >
      Schneier on Security, "Side-Channel Attacks Against LLMs"
      (Feb 2026). Argues that LLM-serving infrastructure — which
      commonly streams tokens and surfaces progress notifications —
      is a high-yield target for timing-modulated exfiltration.
  - kind: paper
    id: whisper-leak-arxiv-2025-11
    url: https://arxiv.org/abs/2511-whisper-leak
    summary: >
      "Whisper Leak" (arXiv, Nov 2025). >98% AUPRC inference of prompt
      topics from encrypted LLM traffic via packet size and timing
      signatures. MCP tools that modulate sleep on conditional input
      are a direct application of the same primitive to the MCP
      response channel.

lethal_edge_cases:
  - >
    Data-gated setTimeout / sleep — the delay argument is derived
    from secret/data via `sleep(secret.charCodeAt(i))`,
    `time.sleep(ord(data[i]) / 1000)`, `setTimeout(cb, secret[i])`.
    One response leaks one byte (or one bit). Classic timing
    covert channel; any content DLP is blind to it.
  - >
    Conditional-delay modulation — `if (bit) await sleep(200); else
    return;`. The delay is binary but the attacker measures
    millisecond-scale jitter and reconstructs a bitstream across
    many calls. Often hidden inside a "rate-limiter" wrapper.
  - >
    Heartbeat / progress-notification timing — the server emits
    MCP progress notifications whose intervals are modulated on
    data (`sendProgress(); await sleep(data[i] * 10);
    sendProgress();`). Cross-references N15: progress notifications
    carry no content but the *interval* does.
  - >
    Retry-After header modulation — server sets `Retry-After:
    <derived from data>` on 429 / 503 responses; the caller logs
    and reconstructs the stream from retry delays. Looks like a
    legitimate backoff knob.
  - >
    Deliberate timeout — `await new Promise(r =>
    setTimeout(r, computeDelay(secret)));` wrapping an otherwise-
    legitimate tool response. The tool returns correct data; only
    the latency carries the exfiltrated payload.
  - >
    Legitimate non-data delays are NOT O8 — fixed rate limiters
    (`setTimeout(cb, 1000)`), exponential backoff
    (`baseDelay * 2 ** retry`), randomised jitter without a
    data-dependent term. The gather step requires the delay
    expression to reference a non-constant, non-counter
    identifier that plausibly holds secret data.

edge_case_strategies:
  - ast-timing-primitive-catalogue
  - data-dependent-delay-expression
  - retry-after-header-modulation
  - progress-notification-timing-cross-ref
  - honest-refusal-no-timing-primitive

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - timing_primitive_with_data_dependency
    - no_constant_delay_observed
  location_kinds:
    - source

obsolescence:
  retire_when: >
    MCP runtimes enforce a constant-time response floor for every
    tool invocation (normalising response latency before emit) or
    the MCP spec declares a typed latency budget that is stripped
    of tool-derived values before reaching the client. Neither
    exists as of 2026-04.

mutations_survived:
  - unicode-homoglyph-identifier
mutations_acknowledged_blind:
  - split-string-literal
  - base64-wrap-payload
---

# O8 — Timing-Based Covert Channel

## Threat Model

The timing channel is the last channel every content-inspection
pipeline misses. A malicious MCP tool responds correctly but gates
its response latency on secret bytes: `sleep(secret.charCodeAt(i))`,
`time.sleep(ord(data[i]) / 1000)`, or conditional `await sleep(200)
if bit else return`. Over many calls the attacker reconstructs the
secret from the delays alone.

Schneier (Feb 2026) and the "Whisper Leak" paper (Nov 2025) show
that LLM serving infrastructure — where progress notifications and
streaming tokens already surface timing signals — is an especially
high-yield target for this primitive applied to the MCP response
channel.

## Detection Strategy — Static AST Surface

The gather step walks the AST for five shapes:

1. `setTimeout(cb, <arg>)` / `setImmediate` / `setInterval` where
   `<arg>` is NOT a numeric literal / counter / configured constant.
2. `await new Promise(r => setTimeout(r, <arg>))` — same check on
   the nested arg.
3. `time.sleep(<arg>)` / `asyncio.sleep(<arg>)` — Python AST /
   identifier walk (on TypeScript-transpiled Python shapes).
4. `res.setHeader("Retry-After", <arg>)` / `reply.header(...)` where
   `<arg>` is not a constant.
5. `sendProgress(...)` / `notification.progress(...)` sandwiched
   around a non-constant sleep (cross-ref N15).

"Not a numeric literal / counter / configured constant" means the
argument reads an identifier whose name does NOT match the small
counter-like vocabulary (`retryCount`, `attempt`, `delayMs`,
`RATE_LIMIT_MS`, …). This is a weak but necessary heuristic — the
CHARTER confidence cap (0.72) reflects it.

## Honest-refusal Gate

If the source contains no timing primitive at all
(`setTimeout` / `sleep` / `setImmediate` / `performance.now`),
the rule returns immediately. No finding is produced. This is the
single largest driver of false-positive reduction.

## Confidence Cap

**0.72** — timing is a weak static signal. Even a correct match
requires runtime confirmation (a constant-time response floor is
the true fix). The cap holds reviewer headroom; confidence above
0.72 would overstate what static analysis can prove.
