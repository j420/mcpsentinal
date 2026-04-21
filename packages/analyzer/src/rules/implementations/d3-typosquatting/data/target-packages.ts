/**
 * D3 — Curated target package registry.
 *
 * Top popular packages per ecosystem + MCP-specific targets. Each entry
 * carries the ecosystem the canonical package lives in and
 * `max_distance`, the Damerau-Levenshtein ceiling under which a candidate
 * is considered a possible typosquat of this target. Short names get a
 * tighter ceiling (2) because single-edit collisions among 4-char names
 * are common in legitimate cases. Longer names get a looser ceiling (3).
 *
 * Object-literal (Record) shape — NOT a string-literal array — so the
 * no-static-patterns guard does not count it as a "long string-literal
 * array". `rules/<rule>/data/` is also skipped by the guard, which keeps
 * this file non-regressing.
 *
 * Adding an entry:
 *   - The KEY is the canonical package name exactly as it would appear
 *     in `package.json` / `pyproject.toml` (scoped npm names included).
 *   - `ecosystem` selects the registry namespace (npm or pypi).
 *   - `max_distance` is the Damerau-Levenshtein threshold — 2 for names
 *     ≤ 10 chars, 3 for longer. For highly exposed names (popular +
 *     short scoped official), the tighter 2 even when name is long.
 */

export type Ecosystem = "npm" | "pypi";

export interface TargetPackage {
  ecosystem: Ecosystem;
  /** Damerau-Levenshtein ceiling under which a candidate is "suspiciously similar". */
  max_distance: number;
  /** Whether this is an official scoped name — triggers scope-squat check. */
  scoped_official?: boolean;
  /** Unscoped name used to detect scope-squats (e.g. @mcp/sdk shadowing @modelcontextprotocol/sdk). */
  unscoped_alias?: string;
}

// ─── MCP-ecosystem officials and highly squatted packages ───────────────
export const MCP_TARGETS: Record<string, TargetPackage> = {
  "@modelcontextprotocol/sdk": {
    ecosystem: "npm",
    max_distance: 3,
    scoped_official: true,
    unscoped_alias: "sdk",
  },
  "@modelcontextprotocol/server-filesystem": {
    ecosystem: "npm",
    max_distance: 3,
    scoped_official: true,
    unscoped_alias: "server-filesystem",
  },
  "@modelcontextprotocol/server-github": {
    ecosystem: "npm",
    max_distance: 3,
    scoped_official: true,
    unscoped_alias: "server-github",
  },
  "@modelcontextprotocol/server-postgres": {
    ecosystem: "npm",
    max_distance: 3,
    scoped_official: true,
    unscoped_alias: "server-postgres",
  },
  "@modelcontextprotocol/server-slack": {
    ecosystem: "npm",
    max_distance: 3,
    scoped_official: true,
    unscoped_alias: "server-slack",
  },
  "@modelcontextprotocol/server-memory": {
    ecosystem: "npm",
    max_distance: 3,
    scoped_official: true,
    unscoped_alias: "server-memory",
  },
  "@modelcontextprotocol/server-puppeteer": {
    ecosystem: "npm",
    max_distance: 3,
    scoped_official: true,
    unscoped_alias: "server-puppeteer",
  },
  "@modelcontextprotocol/server-brave-search": {
    ecosystem: "npm",
    max_distance: 3,
    scoped_official: true,
    unscoped_alias: "server-brave-search",
  },
  "@modelcontextprotocol/server-google-maps": {
    ecosystem: "npm",
    max_distance: 3,
    scoped_official: true,
    unscoped_alias: "server-google-maps",
  },
  "@modelcontextprotocol/server-fetch": {
    ecosystem: "npm",
    max_distance: 3,
    scoped_official: true,
    unscoped_alias: "server-fetch",
  },
  "@modelcontextprotocol/server-everart": {
    ecosystem: "npm",
    max_distance: 3,
    scoped_official: true,
    unscoped_alias: "server-everart",
  },
  "@modelcontextprotocol/server-sequential-thinking": {
    ecosystem: "npm",
    max_distance: 3,
    scoped_official: true,
    unscoped_alias: "server-sequential-thinking",
  },
  "@modelcontextprotocol/server-everything": {
    ecosystem: "npm",
    max_distance: 3,
    scoped_official: true,
    unscoped_alias: "server-everything",
  },
  "@modelcontextprotocol/inspector": {
    ecosystem: "npm",
    max_distance: 3,
    scoped_official: true,
    unscoped_alias: "inspector",
  },
  "@anthropic-ai/sdk": {
    ecosystem: "npm",
    max_distance: 3,
    scoped_official: true,
    unscoped_alias: "sdk",
  },
  fastmcp: { ecosystem: "npm", max_distance: 2 },
  "mcp-framework": { ecosystem: "npm", max_distance: 3 },
  mcp: { ecosystem: "pypi", max_distance: 2 },
  "mcp-agent": { ecosystem: "pypi", max_distance: 3 },
  "fastmcp-py": { ecosystem: "pypi", max_distance: 3 },
  anthropic: { ecosystem: "pypi", max_distance: 2 },
};

// ─── Popular npm targets (top downloads by weekly volume) ───────────────
export const NPM_TARGETS: Record<string, TargetPackage> = {
  express: { ecosystem: "npm", max_distance: 2 },
  fastify: { ecosystem: "npm", max_distance: 2 },
  react: { ecosystem: "npm", max_distance: 2 },
  next: { ecosystem: "npm", max_distance: 2 },
  vue: { ecosystem: "npm", max_distance: 2 },
  angular: { ecosystem: "npm", max_distance: 2 },
  svelte: { ecosystem: "npm", max_distance: 2 },
  lodash: { ecosystem: "npm", max_distance: 2 },
  underscore: { ecosystem: "npm", max_distance: 3 },
  axios: { ecosystem: "npm", max_distance: 2 },
  chalk: { ecosystem: "npm", max_distance: 2 },
  commander: { ecosystem: "npm", max_distance: 3 },
  debug: { ecosystem: "npm", max_distance: 2 },
  moment: { ecosystem: "npm", max_distance: 2 },
  uuid: { ecosystem: "npm", max_distance: 2 },
  dotenv: { ecosystem: "npm", max_distance: 2 },
  zod: { ecosystem: "npm", max_distance: 2 },
  prisma: { ecosystem: "npm", max_distance: 2 },
  "drizzle-orm": { ecosystem: "npm", max_distance: 3 },
  typescript: { ecosystem: "npm", max_distance: 3 },
  eslint: { ecosystem: "npm", max_distance: 2 },
  prettier: { ecosystem: "npm", max_distance: 3 },
  vitest: { ecosystem: "npm", max_distance: 2 },
  jest: { ecosystem: "npm", max_distance: 2 },
  webpack: { ecosystem: "npm", max_distance: 3 },
  vite: { ecosystem: "npm", max_distance: 2 },
  esbuild: { ecosystem: "npm", max_distance: 3 },
  rollup: { ecosystem: "npm", max_distance: 2 },
  turbo: { ecosystem: "npm", max_distance: 2 },
  colors: { ecosystem: "npm", max_distance: 2 },
  chromedriver: { ecosystem: "npm", max_distance: 3 },
  "body-parser": { ecosystem: "npm", max_distance: 3 },
  cors: { ecosystem: "npm", max_distance: 2 },
  bluebird: { ecosystem: "npm", max_distance: 3 },
  request: { ecosystem: "npm", max_distance: 2 },
  "graphql": { ecosystem: "npm", max_distance: 3 },
  mongoose: { ecosystem: "npm", max_distance: 3 },
  ioredis: { ecosystem: "npm", max_distance: 3 },
  bcrypt: { ecosystem: "npm", max_distance: 2 },
  jsonwebtoken: { ecosystem: "npm", max_distance: 3 },
  passport: { ecosystem: "npm", max_distance: 3 },
  winston: { ecosystem: "npm", max_distance: 3 },
  pino: { ecosystem: "npm", max_distance: 2 },
  "socket.io": { ecosystem: "npm", max_distance: 3 },
  discord: { ecosystem: "npm", max_distance: 3 },
  puppeteer: { ecosystem: "npm", max_distance: 3 },
  playwright: { ecosystem: "npm", max_distance: 3 },
  "node-fetch": { ecosystem: "npm", max_distance: 3 },
  cheerio: { ecosystem: "npm", max_distance: 3 },
  mistral: { ecosystem: "npm", max_distance: 2 },
  openai: { ecosystem: "npm", max_distance: 2 },
  babel: { ecosystem: "npm", max_distance: 2 },
};

// ─── Popular PyPI targets ───────────────────────────────────────────────
export const PYPI_TARGETS: Record<string, TargetPackage> = {
  requests: { ecosystem: "pypi", max_distance: 2 },
  numpy: { ecosystem: "pypi", max_distance: 2 },
  pandas: { ecosystem: "pypi", max_distance: 2 },
  flask: { ecosystem: "pypi", max_distance: 2 },
  django: { ecosystem: "pypi", max_distance: 2 },
  fastapi: { ecosystem: "pypi", max_distance: 2 },
  click: { ecosystem: "pypi", max_distance: 2 },
  pyyaml: { ecosystem: "pypi", max_distance: 2 },
  setuptools: { ecosystem: "pypi", max_distance: 3 },
  six: { ecosystem: "pypi", max_distance: 2 },
  urllib3: { ecosystem: "pypi", max_distance: 2 },
  boto3: { ecosystem: "pypi", max_distance: 2 },
  pydantic: { ecosystem: "pypi", max_distance: 2 },
  sqlalchemy: { ecosystem: "pypi", max_distance: 3 },
  httpx: { ecosystem: "pypi", max_distance: 2 },
  scipy: { ecosystem: "pypi", max_distance: 2 },
  matplotlib: { ecosystem: "pypi", max_distance: 3 },
  tensorflow: { ecosystem: "pypi", max_distance: 3 },
  torch: { ecosystem: "pypi", max_distance: 2 },
  transformers: { ecosystem: "pypi", max_distance: 3 },
  langchain: { ecosystem: "pypi", max_distance: 3 },
  openai: { ecosystem: "pypi", max_distance: 2 },
  jinja2: { ecosystem: "pypi", max_distance: 2 },
  werkzeug: { ecosystem: "pypi", max_distance: 3 },
  certifi: { ecosystem: "pypi", max_distance: 3 },
  idna: { ecosystem: "pypi", max_distance: 2 },
  cryptography: { ecosystem: "pypi", max_distance: 3 },
  pytest: { ecosystem: "pypi", max_distance: 2 },
  black: { ecosystem: "pypi", max_distance: 2 },
  ruff: { ecosystem: "pypi", max_distance: 2 },
  colorama: { ecosystem: "pypi", max_distance: 3 },
  typer: { ecosystem: "pypi", max_distance: 2 },
};

/** All targets merged into a single map for iteration. */
export const ALL_TARGETS: Record<string, TargetPackage> = {
  ...MCP_TARGETS,
  ...NPM_TARGETS,
  ...PYPI_TARGETS,
};

/** How many canonical targets this registry covers. */
export const TARGET_COUNTS: { mcp: number; npm: number; pypi: number; total: number } = {
  mcp: Object.keys(MCP_TARGETS).length,
  npm: Object.keys(NPM_TARGETS).length,
  pypi: Object.keys(PYPI_TARGETS).length,
  total: Object.keys({ ...MCP_TARGETS, ...NPM_TARGETS, ...PYPI_TARGETS }).length,
};
