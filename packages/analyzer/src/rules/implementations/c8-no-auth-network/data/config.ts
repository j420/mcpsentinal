/**
 * C8 — No Auth on Network Interface: rule-specific config data.
 *
 * Lives under `data/` so the no-static-patterns guard skips the directory.
 */

/** Method names that bind a server to a network interface. */
export const LISTEN_METHODS: ReadonlySet<string> = new Set([
  "listen",
  "bind",
]);

/** Identifier names commonly bound to an auth middleware. */
export const AUTH_MIDDLEWARE_TOKENS: ReadonlySet<string> = new Set([
  "auth",
  "authenticate",
  "authMiddleware",
  "requireAuth",
  "passport",
  "jwt",
  "bearer",
  "apiKey",
  "session",
  "verifyToken",
  "verifyJwt",
  "verifyApiKey",
]);

/** Hosts that mean "all network interfaces". */
export const ALL_INTERFACE_HOSTS: ReadonlySet<string> = new Set([
  "0.0.0.0",
  "::",
  "::0",
]);

/** Hosts that mean "loopback only" — these are NOT a leak. */
export const LOOPBACK_HOSTS: ReadonlySet<string> = new Set([
  "127.0.0.1",
  "localhost",
  "::1",
]);

/**
 * Python auth markers — substrings whose presence anywhere in the
 * source signals that an authentication framework is wired in.
 * Lives in data/ so the no-static-patterns guard skips the array.
 */
export const PYTHON_AUTH_MARKERS: ReadonlySet<string> = new Set([
  "Depends(get_current_user",
  "Depends(verify",
  "OAuth2PasswordBearer",
  "HTTPBearer",
  "@requires_auth",
  "verify_jwt",
  "verify_api_key",
]);
