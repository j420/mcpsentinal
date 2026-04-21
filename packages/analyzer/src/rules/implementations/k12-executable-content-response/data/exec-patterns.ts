/**
 * K12 executable-content vocabulary.
 *
 * Two classes:
 *   - EXEC_CALL_IDENTIFIERS — bare function call names that construct
 *     executable code: eval, Function (via `new Function`), require,
 *     dynamic import(). Detection matches CallExpression / NewExpression
 *     where the callee tokenises to one of these names.
 *   - EXEC_STRING_MARKERS — token substrings inside string literals that
 *     carry executable semantics when rendered by an AI client: `<script`
 *     (HTML), `javascript:` (URI scheme), `data:text/html`.
 *   - INLINE_EVENT_HANDLER_PREFIXES — attribute-name prefixes that, when
 *     followed by "=\"" / "='", indicate an inline event handler
 *     (onclick, onerror, onload, …). Detection scans string literals
 *     character-by-character — no regex.
 */

/** CallExpression identifiers whose invocation is a code-execution primitive. */
export const EXEC_CALL_IDENTIFIERS: Record<string, true> = {
  eval: true,
  require: true,
};

/** Constructor identifiers in NewExpression that create executable objects. */
export const EXEC_NEW_IDENTIFIERS: Record<string, true> = {
  function: true,
  asyncfunction: true,
  generatorfunction: true,
};

/** Token substrings inside string literals indicating embedded executable content. */
export const EXEC_STRING_MARKERS: Record<string, true> = {
  "<script": true,
  "</script": true,
  "javascript:": true,
  "data:text/html": true,
};

/** HTML attribute-name prefixes for inline event handlers. */
export const INLINE_EVENT_HANDLER_PREFIXES: Record<string, true> = {
  onclick: true,
  onerror: true,
  onload: true,
  onmouseover: true,
  onmouseout: true,
  onfocus: true,
  onblur: true,
  onsubmit: true,
  onchange: true,
  onkeydown: true,
  onkeyup: true,
  onkeypress: true,
  onbeforeload: true,
};

/**
 * Sanitizer identifiers / methods whose presence in the enclosing scope
 * counts as a mitigation. Split:
 *   - bare-call: escapeHtml(), sanitize(), encodeURIComponent()
 *   - receiver.method: DOMPurify.sanitize(), he.encode()
 */
export const SANITIZER_CALL_IDENTIFIERS: Record<string, true> = {
  escapehtml: true,
  escapehtmlentity: true,
  sanitize: true,
  sanitizehtml: true,
  encodehtml: true,
  encodeuricomponent: true,
  encodeuri: true,
  textcontent: true,
  createtextnode: true,
};

export const SANITIZER_RECEIVER_METHODS: Record<string, Record<string, true>> = {
  dompurify: { sanitize: true },
  he: { encode: true, escape: true },
  validator: { escape: true },
  xss: { inhtml: true, escapehtml: true },
};

/**
 * Response-emitting call identifiers — the sink where response content is
 * handed to the outside world. Detection looks for CallExpression with
 * PropertyAccess: receiver ∈ RESPONSE_RECEIVERS, method ∈ RESPONSE_METHODS.
 */
export const RESPONSE_RECEIVERS: Record<string, true> = {
  res: true,
  response: true,
  resp: true,
  reply: true,
  ctx: true,
};

export const RESPONSE_METHODS: Record<string, true> = {
  send: true,
  json: true,
  write: true,
  end: true,
  html: true,
  body: true,
  render: true,
  status: true,
};
