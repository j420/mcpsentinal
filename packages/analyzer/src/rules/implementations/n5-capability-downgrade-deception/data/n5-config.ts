/**
 * N5 — Rule-local configuration (confidence cap + vocabulary).
 */

/** Handler-registration fragment shapes the scanner recognises. */
export const HANDLER_REGISTRATION_FRAGMENTS: Readonly<Record<string, string>> =
  {
    setrequesthandler: "server.setRequestHandler",
    onrequest: "server.onRequest",
    handle_method: "handle_method(",
    "addmethodhandler": "addMethodHandler",
    "register_handler": "register_handler",
  };

/** Capability-declaration fragment shapes — "capabilities" near false / null. */
export const CAPABILITY_DECLARATION_FRAGMENTS: Readonly<Record<string, string>> =
  {
    capabilities: "capabilities declaration object",
    servercapabilities: "serverCapabilities declaration",
    server_capabilities: "server_capabilities declaration",
  };

/** Per-capability-key false / absent shapes. */
export const DOWNGRADE_VALUES: Readonly<Record<string, string>> = {
  ": false": "set to false",
  ": null": "set to null",
  "=false": "set to false (python-style)",
  "= false": "set to false",
};

export const N5_CONFIDENCE_CAP = 0.78;
