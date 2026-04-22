export const N15_CONFIDENCE_CAP = 0.88;

/** User-input as method-name dispatch shapes. */
export const USER_DISPATCH_FRAGMENTS: Readonly<Record<string, string>> = {
  "dispatch[req.": "dispatch[req.*] dynamic dispatch",
  "handlers[params.": "handlers[params.*] dynamic dispatch",
  "handlers[req.": "handlers[req.*] dynamic dispatch",
  "routes[req.": "routes[req.*] dynamic dispatch",
  "route[body.": "route[body.*] dynamic dispatch",
};

/** Handler-registration shape fragments. */
export const REGISTRATION_FRAGMENTS: Readonly<Record<string, string>> = {
  setrequesthandler: "server.setRequestHandler",
  onrequest: "server.onRequest",
  "register_handler(": "register_handler(",
  "addhandler(": "addHandler(",
  "dispatch.on(": "dispatch.on(",
};

/**
 * Minimum Levenshtein distance below which a non-canonical handler name
 * is considered a confusion candidate (too close to a canonical spec
 * method).
 */
export const N15_LEVENSHTEIN_MAX_DISTANCE = 2;
