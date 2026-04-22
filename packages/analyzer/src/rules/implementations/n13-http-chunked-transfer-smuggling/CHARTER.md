---
rule_id: N13
interface_version: v2
severity: critical
owasp: MCP07-insecure-config
mitre: AML.T0054
risk_domain: protocol-transport

threat_refs:
  - kind: cve
    id: CVE-2025-6515
    summary: >
      CVE-2025-6515 documented MCP Streamable HTTP session-hijacking.
      HTTP request smuggling (Transfer-Encoding vs Content-Length
      disagreement) is a related class: when two HTTP parsers disagree
      on where one request ends and the next begins, an attacker can
      splice a request into the victim's session. In the MCP context
      this can hijack an agent's HTTP-based session or inject forged
      JSON-RPC requests.
  - kind: paper
    id: PortSwigger-HTTP-Request-Smuggling
    url: https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn
    summary: >
      PortSwigger's 2019 "HTTP Desync" research catalogued smuggling via
      Transfer-Encoding / Content-Length disagreement, conflicting chunk
      extensions, and hand-rolled chunked parsers. N13 targets the
      server-side code shapes that enable this class against MCP
      Streamable HTTP transports.
  - kind: spec
    id: MCP-2025-03-26-Streamable-HTTP
    url: https://modelcontextprotocol.io/specification/2025-03-26/basic/transports#streamable-http
    summary: >
      The 2025-03-26 Streamable HTTP transport uses standard HTTP/1.1
      chunked encoding. Most MCP servers delegate parsing to the
      platform HTTP stack. The threat surface N13 targets is servers
      that hand-roll chunked framing or explicitly set conflicting
      transfer headers.

lethal_edge_cases:
  - >
    Response / request handler explicitly sets both `Transfer-Encoding:
    chunked` AND `Content-Length`. Two parsers disagree on the correct
    framing; the attacker exploits the disagreement by positioning the
    intermediary at the Content-Length boundary and the backend at the
    chunked boundary (or vice versa). Injects a second request into
    the victim's session.
  - >
    Hand-rolled chunked encoding using raw `\r\n0\r\n` terminator
    construction. Any off-by-one error in the chunk-size field allows
    the parser to consume into the next request. Most HTTP libraries
    disallow this pattern — hand-rolled code is a strong signal of
    bypass.
  - >
    Chunk-extension abuse. The chunk line format permits extensions
    (`<size>;<ext>=<val>\r\n`). A parser that ignores extensions while
    another one treats them as part of the size field is a desync
    vector.
  - >
    Raw socket write of HTTP framing from user-controlled bytes. The
    server accepts a body and echoes it into a `net.Socket.write` call
    that constructs chunked responses. Attacker chooses the bytes that
    land in the framing path.

edge_case_strategies:
  - conflicting-transfer-headers-scan
  - raw-chunked-terminator-scan
  - chunk-extension-abuse-scan
  - socket-write-user-bytes-scan

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - chunked_framing_manipulated
  location_kinds:
    - source

obsolescence:
  retire_when: >
    MCP SDKs mandate the use of well-tested HTTP libraries for Streamable
    HTTP transports, and explicit Transfer-Encoding / Content-Length
    manipulation is disallowed at the framework layer.
---

# N13 — HTTP Chunked Transfer Smuggling

Honest-refusal: only fires when a Streamable-HTTP / HTTP transport
marker is present in the file. Confidence cap 0.82.
