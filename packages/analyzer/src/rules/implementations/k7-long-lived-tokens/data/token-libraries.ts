/**
 * K7 token-creation library vocabulary.
 *
 * Identifies CallExpression symbols that create JWTs / access tokens /
 * refresh tokens. Detection at the AST layer matches the call's symbol
 * (final identifier of the callee chain) against TOKEN_METHODS and the
 * receiver (when present) against TOKEN_RECEIVERS. Requiring BOTH is
 * what keeps false-positives low: a bare `sign(...)` call is common in
 * cryptography utilities that are unrelated to token issuance.
 */

/**
 * Identifier names of the final method in token-creation call chains.
 * Exact case-insensitive token match. Presence alone is insufficient;
 * the receiver must be in TOKEN_RECEIVERS (see gather-ast.ts).
 */
export const TOKEN_METHODS: Record<string, true> = {
  sign: true,
  signasync: true,
  signjwt: true,
  signjwe: true,
  signjws: true,
  createtoken: true,
  generatetoken: true,
  signtoken: true,
  issuetoken: true,
  maketoken: true,
};

/**
 * Call receivers (PropertyAccessExpression.expression) that identify the
 * token-creation context. Match the receiver's bare identifier (case-
 * insensitive) against this set OR match its tail segment (for chains
 * like `jose.SignJWT.prototype.sign`).
 */
export const TOKEN_RECEIVERS: Record<string, true> = {
  jwt: true,
  jsonwebtoken: true,
  jose: true,
  signjwt: true,
  jwtio: true,
  jwthelper: true,
  jwtservice: true,
  tokenservice: true,
  tokenmanager: true,
  tokenissuer: true,
  auth: true,
  authservice: true,
};

/**
 * Function identifiers treated as token-creation calls WITHOUT a
 * receiver. Used for bare-call forms like `signToken(payload)` or
 * `issueToken(...)` where the author has aliased a library function.
 */
export const BARE_TOKEN_CREATION_CALLS: Record<string, true> = {
  signtoken: true,
  createtoken: true,
  generatetoken: true,
  issuetoken: true,
  maketoken: true,
  mintjwt: true,
  mintjwe: true,
};
