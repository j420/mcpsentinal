import type { RuleFixtureSet } from "../types.js";

const base = {
  server: { id: "test", name: "test-server", description: null, github_url: null },
  tools: [],
  dependencies: [],
  connection_metadata: null,
};

function srcCtx(source_code: string) {
  return { ...base, source_code };
}

// ── C1: Command Injection ──────────────────────────────────────────────────────
export const C1: RuleFixtureSet = {
  rule_id: "C1",
  rule_name: "Command Injection",
  fixtures: [
    {
      description: "exec() with user input — basic",
      context: srcCtx(`const { exec } = require('child_process');
exec(userInput, (err, stdout) => res.send(stdout));`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "execSync with string concatenation",
      context: srcCtx(`execSync("ls " + req.body.path);`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Template literal in exec",
      context: srcCtx("exec(`ls ${req.query.dir}`);"),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "child_process import present",
      context: srcCtx(`import { exec } from 'child_process';
exec(args.command);`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Python subprocess with shell=True",
      context: srcCtx(`import subprocess
subprocess.run(cmd, shell=True)`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Python os.system",
      context: srcCtx(`import os
os.system(user_input)`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "shelljs exec",
      context: srcCtx(`const shell = require('shelljs');
shell.exec(userCmd);`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "vm.runInNewContext with user input",
      context: srcCtx(`const vm = require('vm');
vm.runInNewContext(userCode, sandbox);`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "spawnSync with shell: true",
      context: srcCtx(`spawnSync('bash', ['-c', userInput], { shell: true });`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe: execFile with array args",
      context: srcCtx(`const { execFile } = require('child_process');
execFile('/usr/bin/git', ['status', '--porcelain'], callback);`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe: spawn with array args — no shell",
      context: srcCtx(`const proc = spawn('ls', ['-la', sanitizedPath]);`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Comment mentioning exec — not actual call",
      context: srcCtx(`// We do not use exec() here for security reasons.
const result = fs.readFileSync(path);`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "SQL execute — not OS command",
      context: srcCtx(`await db.execute("SELECT * FROM users WHERE id = ?", [userId]);`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Edge case: Python subprocess without shell=True (safe)",
      context: srcCtx(`subprocess.run(['git', 'status'])`),
      expect_finding: false,
      kind: "edge_case",
    },
    {
      description: "Edge case: execSync with hardcoded string — no user input",
      context: srcCtx(`execSync('git --version');`),
      expect_finding: true, // still matches pattern (execSync present) — rule is conservative
      kind: "edge_case",
    },
    // ── Adversarial mutations (bypass techniques the rule must still catch) ──
    {
      description: "adversarial alias-rename execSync",
      context: srcCtx(`const { execSync } = require('child_process');
const runCmd = execSync;
runCmd(req.body.cmd);`),
      expect_finding: true,
      kind: "edge_case",
      threat_ref: "C1-adv1-alias-rename",
    },
    {
      description: "adversarial base64-wrapped eval",
      context: srcCtx(`const payload = Buffer.from(req.query.data, 'base64').toString();
eval(payload);`),
      expect_finding: true,
      kind: "edge_case",
      threat_ref: "C1-adv2-base64-wrapped",
    },
    {
      description: "adversarial spread-args join",
      context: srcCtx(`const { exec } = require('child_process');
const parts = ['git', 'log', req.query.ref];
exec(parts.join(' '));`),
      expect_finding: true,
      kind: "edge_case",
      threat_ref: "C1-adv3-spread-args",
    },
    {
      description: "adversarial unicode homoglyph parameter",
      // Parameter name uses Cyrillic 'о' (U+043E) instead of Latin 'o'
      context: srcCtx(`function runTool(соmmand) {
  const { execSync } = require('child_process');
  execSync(соmmand);
}`),
      expect_finding: true,
      kind: "edge_case",
      threat_ref: "C1-adv4-unicode-homoglyph",
    },
    // ── Additional negative controls ──
    {
      description: "Safe: shellQuote escape library wraps user input",
      context: srcCtx(`const shellQuote = require('shell-quote');
const safeArg = shellQuote.quote([userInput]);
exec(\`git log \${safeArg}\`);`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe: allowlist indirection, no user input reaches sink",
      context: srcCtx(`const ALLOWED = { status: 'git status', log: 'git log' };
const cmd = ALLOWED[req.query.action];
if (!cmd) throw new Error('bad action');
exec(cmd);`),
      expect_finding: false,
      kind: "true_negative",
    },
  ],
};

// ── C2: Path Traversal ────────────────────────────────────────────────────────
export const C2: RuleFixtureSet = {
  rule_id: "C2",
  rule_name: "Path Traversal",
  fixtures: [
    {
      description: "String concatenation with user input in file path",
      context: srcCtx(`const data = fs.readFileSync('/uploads/' + req.params.file);`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Literal ../ in path",
      context: srcCtx(`const path = '../../../etc/passwd';`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "URL-encoded traversal %2e%2e",
      context: srcCtx(`const resolved = req.query.path.replace('%2e%2e', '');`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Null byte in path",
      context: srcCtx(`const file = req.query.name + '\\x00.txt';`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Python open with user-controlled path",
      context: srcCtx(`with open(os.path.join('/data', user_path)) as f:`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe: path.resolve + chroot check",
      context: srcCtx(`const abs = path.resolve(ROOT, userPath);
if (!abs.startsWith(ROOT)) throw new Error('path traversal');`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe: hardcoded path, no user input",
      context: srcCtx(`const config = fs.readFileSync('/etc/app/config.json');`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Edge case: path.join that still allows traversal",
      context: srcCtx(`const full = path.join(baseDir, userInput);
return fs.readFileSync(full);`),
      expect_finding: true,
      kind: "edge_case",
    },
    {
      description: "Edge case: double-encoded traversal ..%252f..",
      context: srcCtx(`const decoded = decodeURIComponent(req.query.path);
// path: ..%252f..%252fetc%252fpasswd`),
      expect_finding: true,
      kind: "edge_case",
    },
  ],
};

// ── C4: SQL Injection ─────────────────────────────────────────────────────────
export const C4: RuleFixtureSet = {
  rule_id: "C4",
  rule_name: "SQL Injection",
  fixtures: [
    {
      description: "String concatenation in SQL query",
      context: srcCtx(`db.query("SELECT * FROM users WHERE name = '" + username + "'");`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Template literal in SQL",
      context: srcCtx("db.query(`SELECT * FROM users WHERE id = ${userId}`);"),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Python f-string SQL",
      context: srcCtx("cursor.execute(f\"SELECT * FROM orders WHERE user_id = {uid}\")"),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Python string concatenation in execute",
      context: srcCtx(`cursor.execute("SELECT * FROM users WHERE email = '" + email + "'")`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe: parameterized query with ?",
      context: srcCtx(`db.query("SELECT * FROM users WHERE id = ?", [userId]);`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe: ORM with parameterized query",
      context: srcCtx(`User.findOne({ where: { id: userId } });`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe: Python parameterized execute",
      context: srcCtx(`cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Edge case: query builder that might bypass parameterization",
      context: srcCtx(`const q = knex.raw("SELECT * FROM ?? WHERE id = " + id, [table]);`),
      expect_finding: true,
      kind: "edge_case",
    },
  ],
};

// ── C5: Hardcoded Secrets ─────────────────────────────────────────────────────
export const C5: RuleFixtureSet = {
  rule_id: "C5",
  rule_name: "Hardcoded Secrets",
  fixtures: [
    {
      description: "Hardcoded OpenAI API key",
      context: srcCtx(`const client = new OpenAI({ apiKey: "sk-proj-abc123XYZ456def789GHI" });`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Hardcoded GitHub PAT",
      context: srcCtx(`const token = "ghp_16C7e42F292c6912E7710c838347Ae5b9";`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Hardcoded AWS access key",
      context: srcCtx(`const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Hardcoded Anthropic API key",
      context: srcCtx(`const client = new Anthropic({ apiKey: "sk-ant-api03-abc123-xyz" });`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Hardcoded Stripe live secret key",
      context: srcCtx(`const stripe = new Stripe("sk_live_51AbcDEFghijklmnopqrstuvwxyz");`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "SSH private key PEM block",
      context: srcCtx(`const key = \`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4xBXD...
-----END RSA PRIVATE KEY-----\`;`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Hardcoded JWT token",
      context: srcCtx(
        `const token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";`
      ),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Hardcoded Slack bot token",
      context: srcCtx(`const slack_token = "xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuvwx";`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Environment variable — not hardcoded",
      context: srcCtx(`const apiKey = process.env.OPENAI_API_KEY;`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Config file read — not hardcoded",
      context: srcCtx(`const { apiKey } = JSON.parse(fs.readFileSync('.config.json'));`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Placeholder/example key in comments",
      context: srcCtx(`// Example: const key = "sk-proj-REPLACE_ME_WITH_REAL_KEY";`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Edge case: key in test fixture (still should flag)",
      context: srcCtx(`// test credentials
const TEST_KEY = "AKIAIOSFODNN7TESTKEY1";`),
      expect_finding: true,
      kind: "edge_case",
    },
    {
      description: "Databricks dapi token",
      context: srcCtx(`const token = "dapi1234567890abcdef1234567890abcdef";`),
      expect_finding: true,
      kind: "true_positive",
    },
  ],
};

// ── C10: Prototype Pollution ──────────────────────────────────────────────────
export const C10: RuleFixtureSet = {
  rule_id: "C10",
  rule_name: "Prototype Pollution",
  fixtures: [
    {
      description: "Direct __proto__ assignment",
      context: srcCtx(`obj[req.body.key] = req.body.value;
// if key is '__proto__', pollutes prototype`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "constructor.prototype manipulation",
      context: srcCtx(`obj.constructor.prototype.isAdmin = true;`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "lodash merge with user input (CVE-2019-10744)",
      context: srcCtx(`const _ = require('lodash');
_.merge(config, userInput);`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Object.assign with user-controlled keys",
      context: srcCtx(`Object.assign(target, JSON.parse(req.body));`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "deepmerge with untrusted input",
      context: srcCtx(`const merged = deepmerge(defaults, userOptions);`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe merge with Object.create(null) base",
      context: srcCtx(`const safe = Object.assign(Object.create(null), userInput);`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Object.assign with non-user-controlled objects",
      context: srcCtx(`const config = Object.assign({}, defaults, overrides);`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Edge case: __proto__ check as defense mechanism",
      context: srcCtx(`if (key === '__proto__' || key === 'constructor') throw new Error();`),
      expect_finding: true, // still matches __proto__ pattern — conservative
      kind: "edge_case",
    },
  ],
};

// ── C12: Unsafe Deserialization ───────────────────────────────────────────────
export const C12: RuleFixtureSet = {
  rule_id: "C12",
  rule_name: "Unsafe Deserialization",
  fixtures: [
    {
      description: "Python pickle.loads on user input",
      context: srcCtx(`import pickle
data = pickle.loads(user_data)`),
      expect_finding: true,
      kind: "true_positive",
      threat_ref: "CVE-2023-pickle-rce",
    },
    {
      description: "Python yaml.load without SafeLoader",
      context: srcCtx(`import yaml
config = yaml.load(user_config)`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "node-serialize (CVE-2017-5941)",
      context: srcCtx(`const serialize = require('node-serialize');
const obj = serialize.unserialize(req.body.data);`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Python marshal.loads",
      context: srcCtx(`import marshal
obj = marshal.loads(raw_data)`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe: yaml.safe_load",
      context: srcCtx(`import yaml
config = yaml.safe_load(config_str)`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe: JSON.parse — not deserialization",
      context: srcCtx(`const data = JSON.parse(req.body);`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Edge case: yaml.load with Loader=SafeLoader",
      context: srcCtx(`yaml.load(data, Loader=yaml.SafeLoader)`),
      expect_finding: false,
      kind: "edge_case",
    },
  ],
};

// ── C14: JWT Algorithm Confusion ──────────────────────────────────────────────
export const C14: RuleFixtureSet = {
  rule_id: "C14",
  rule_name: "JWT Algorithm Confusion",
  fixtures: [
    {
      description: "JWT verify accepting 'none' algorithm",
      context: srcCtx(`jwt.verify(token, secret, { algorithms: ['none', 'HS256'] });`),
      expect_finding: true,
      kind: "true_positive",
      threat_ref: "CVE-2015-9235",
    },
    {
      description: "PyJWT with verify=False",
      context: srcCtx(`payload = jwt.decode(token, options={"verify_signature": False})`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "ignoreExpiration: true",
      context: srcCtx(`jwt.verify(token, secret, { ignoreExpiration: true });`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "No algorithm pinning — accepts all",
      context: srcCtx(`jwt.verify(token, secret); // no algorithms option`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe JWT verify with pinned algorithm",
      context: srcCtx(`jwt.verify(token, secret, { algorithms: ['RS256'] });`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe PyJWT decode with algorithm specified",
      context: srcCtx(`jwt.decode(token, public_key, algorithms=["RS256"])`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Edge case: algorithms array without 'none' but no restrict",
      context: srcCtx(`jwt.verify(token, key, { algorithms: ['HS256', 'HS512'] });`),
      expect_finding: false,
      kind: "edge_case",
    },
  ],
};

// ── C16: Dynamic Code Evaluation with User Input ──────────────────────────────
export const C16: RuleFixtureSet = {
  rule_id: "C16",
  rule_name: "Dynamic Code Evaluation with User Input",
  fixtures: [
    {
      description: "eval() with user input",
      context: srcCtx(`eval(req.body.code);`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "new Function() with user input",
      context: srcCtx(`const fn = new Function(userCode);\nfn();`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "setTimeout with string argument",
      context: srcCtx(`setTimeout(userCode, 0);`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Python exec() with user input",
      context: srcCtx(`exec(user_provided_code)`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Python eval() with user input",
      context: srcCtx(`result = eval(expression)`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "importlib.import_module with user input",
      context: srcCtx(`import importlib
mod = importlib.import_module(user_module_name)`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe: eval on hardcoded string",
      context: srcCtx(`const version = eval("'1.0.0'"); // intentional`),
      expect_finding: true, // still matches — conservative
      kind: "edge_case",
    },
    {
      description: "Safe: setTimeout with function reference",
      context: srcCtx(`setTimeout(() => cleanupFn(), 5000);`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe: dynamic import of known module",
      context: srcCtx(`const mod = await import('./plugins/' + pluginName + '.js');`),
      expect_finding: false, // import() is not eval()
      kind: "true_negative",
    },
  ],
};

// ── C3: SSRF ───────────────────────────────────────────────────────────────────
export const C3: RuleFixtureSet = {
  rule_id: "C3",
  rule_name: "Server-Side Request Forgery (SSRF)",
  fixtures: [
    {
      description: "fetch() with user-supplied URL parameter directly",
      context: srcCtx(`const result = await fetch(req.body.url);
return result.json();`),
      expect_finding: true,
      kind: "true_positive",
      threat_ref: "SSRF via fetch(userInput)",
    },
    {
      description: "axios.get with user-controlled target",
      context: srcCtx(`const resp = await axios.get(params.target);`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "requests.get with user param in Python",
      context: srcCtx(`import requests
resp = requests.get(params['url'])`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "new URL(userInput) construction — indirect SSRF",
      context: srcCtx(`const target = new URL(input.endpoint);
const data = await fetch(target);`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "IMDS endpoint reference — cloud credential theft",
      context: srcCtx(`// fetch metadata
const meta = await fetch('http://169.254.169.254/latest/meta-data/iam/security-credentials/');`),
      expect_finding: true,
      kind: "true_positive",
      threat_ref: "AWS IMDS credential theft via SSRF",
    },
    {
      description: "httpx with user destination in Python",
      context: srcCtx(`import httpx
async with httpx.AsyncClient() as client:
    resp = await client.get(args.destination)`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe: fetch with hardcoded API URL — no user input",
      context: srcCtx(`const resp = await fetch('https://api.github.com/repos/org/repo');`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe: URL validated against allowlist before fetching",
      context: srcCtx(`const allowed_hosts = ['api.example.com'];
if (!isAllowedHost(url, allowed_hosts)) throw new Error('URL not allowed');
const resp = await fetch(url);`),
      expect_finding: false,
      kind: "true_negative",
    },
  ],
};

// ── C6: Error Leakage ──────────────────────────────────────────────────────────
export const C6: RuleFixtureSet = {
  rule_id: "C6",
  rule_name: "Error Message Information Leakage",
  fixtures: [
    {
      description: "Stack trace sent in response body",
      context: srcCtx(`app.use((err, req, res, next) => {
  res.json({ error: err.stack });
});`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "traceback.format_exc() returned to caller in Python",
      context: srcCtx(`import traceback
try:
    result = process()
except Exception as e:
    return {"error": traceback.format_exc()}`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "err.message piped to response in catch handler",
      context: srcCtx(`try {
  await doWork();
} catch (err) {
  res.send({ message: err.message, stack: err.stack });
}`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe: generic error message returned, error logged server-side",
      context: srcCtx(`try {
  await doWork();
} catch (err) {
  logger.error(err);
  res.json({ error: 'Internal server error' });
}`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Stack trace only shown in development mode",
      context: srcCtx(`if (process.env.NODE_ENV === 'development') {
  res.json({ error: err.stack });
} else {
  res.json({ error: 'An error occurred' });
}`),
      expect_finding: false,
      kind: "true_negative",
    },
  ],
};

// ── C7: Wildcard CORS ──────────────────────────────────────────────────────────
export const C7: RuleFixtureSet = {
  rule_id: "C7",
  rule_name: "Wildcard CORS Configuration",
  fixtures: [
    {
      description: "cors() called with origin: '*'",
      context: srcCtx(`const cors = require('cors');
app.use(cors({ origin: '*' }));`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Access-Control-Allow-Origin header set to wildcard",
      context: srcCtx(`res.setHeader('Access-Control-Allow-Origin', '*');`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "allow_origins = ['*'] in Python FastAPI/Starlette",
      context: srcCtx(`from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(CORSMiddleware, allow_origins=["*"])`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe: specific origin allowlist",
      context: srcCtx(`app.use(cors({ origin: 'https://myapp.example.com' }));`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe: CORS configured for localhost only",
      context: srcCtx(`app.use(cors({ origin: ['http://localhost:3000', '127.0.0.1'] }));`),
      expect_finding: false,
      kind: "true_negative",
    },
  ],
};

// ── C8: No Auth on Network Interface ──────────────────────────────────────────
export const C8: RuleFixtureSet = {
  rule_id: "C8",
  rule_name: "No Authentication on Network-Exposed Server",
  fixtures: [
    {
      description: "server.listen on 0.0.0.0 with no auth middleware",
      context: srcCtx(`const server = http.createServer(handler);
server.listen(3000, '0.0.0.0');`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "host = '0.0.0.0' with no bearer/jwt/auth keyword",
      context: srcCtx(`app.listen(8080, '0.0.0.0', () => console.log('running'));`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "INADDR_ANY binding without auth",
      context: srcCtx(`socket.bind(INADDR_ANY, 9000);`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe: auth middleware registered before listen",
      context: srcCtx(`app.use(authMiddleware);
app.use(bearerTokenValidator);
app.listen(3000);`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe: JWT validation in middleware before server start",
      context: srcCtx(`app.use(jwt({ secret: process.env.JWT_SECRET }));
server.listen(3000);`),
      expect_finding: false,
      kind: "true_negative",
    },
  ],
};

// ── C9: Excessive Filesystem Scope ─────────────────────────────────────────────
export const C9: RuleFixtureSet = {
  rule_id: "C9",
  rule_name: "Excessive Filesystem Scope",
  fixtures: [
    {
      description: "readdir('/') — listing root filesystem",
      context: srcCtx(`const entries = fs.readdirSync('/');`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "os.walk('/') — walking entire filesystem in Python",
      context: srcCtx(`import os
for root, dirs, files in os.walk('/'):
    process(root, files)`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "allowed path set to '/' root",
      context: srcCtx(`const allowed_path = '/';
const files = readdir(allowed_path);`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe: readdir restricted to /tmp subdirectory",
      context: srcCtx(`const appDir = '/tmp/myapp';
const entries = fs.readdirSync(appDir);`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe: operation in sandboxed directory",
      context: srcCtx(`const sandbox = path.resolve('./sandbox');
const files = await readdir(sandbox);`),
      expect_finding: false,
      kind: "true_negative",
    },
  ],
};

// ── C11: ReDoS ─────────────────────────────────────────────────────────────────
export const C11: RuleFixtureSet = {
  rule_id: "C11",
  rule_name: "ReDoS — Catastrophic Regex Backtracking",
  fixtures: [
    {
      description: "Nested quantifiers (a+)+ — catastrophic backtracking",
      context: srcCtx(`const re = /(a+)+/;
if (re.test(input)) validate();`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "new RegExp(userInput) — user-controlled pattern compilation",
      context: srcCtx(`const pattern = new RegExp(req.body.pattern);
const matches = text.match(pattern);`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Alternation overlap pattern (a|a)* — polynomial backtracking",
      context: srcCtx(`const badRegex = /(https?|http)*/;
badRegex.test(userContent);`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe: static regex with no nested quantifiers",
      context: srcCtx(`const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
emailRegex.test(input.slice(0, 256));`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe: input bounded with maxLength before regex application",
      context: srcCtx(`const safeInput = input.substring(0, 100);
const re = /^[a-z]+$/;
re.test(safeInput);`),
      expect_finding: false,
      kind: "true_negative",
    },
  ],
};

// ── C13: Server-Side Template Injection ────────────────────────────────────────
export const C13: RuleFixtureSet = {
  rule_id: "C13",
  rule_name: "Server-Side Template Injection (SSTI)",
  fixtures: [
    {
      description: "jinja2.Template(req.body.template) — user input as template",
      context: srcCtx(`import jinja2
template = jinja2.Template(req.body.template)
result = template.render(data=data)`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Handlebars.compile(req.body.markup) — user-controlled template",
      context: srcCtx(`const Handlebars = require('handlebars');
const tmpl = Handlebars.compile(req.body.markup);
return tmpl(context);`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "eval with template literal containing user input",
      context: srcCtx("eval(`result = ${req.query.expression}`);"),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "nunjucks.renderString with user-supplied template string",
      context: srcCtx(`const nunjucks = require('nunjucks');
const output = nunjucks.renderString(input.template, vars);`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe: static template file with user data as context variables",
      context: srcCtx(`const template = fs.readFileSync('templates/email.html', 'utf8');
const result = Handlebars.compile(template)({ name: user.name });`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe: render_template with static file and autoescape",
      context: srcCtx(`from flask import render_template
return render_template('index.html', data=sanitized_data)`),
      expect_finding: false,
      kind: "true_negative",
    },
  ],
};

// ── C15: Timing Attack on Secret Comparison ─────────────────────────────────────
export const C15: RuleFixtureSet = {
  rule_id: "C15",
  rule_name: "Timing Attack on Secret or Token Comparison",
  fixtures: [
    {
      description: "API key compared with === — timing-unsafe",
      context: srcCtx(`if (apiKey === req.headers.authorization) {
  allowAccess();
}`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "HMAC signature compared with == in Python — timing leak",
      context: srcCtx(`if hmac_expected == provided_hmac:
    verify_signature()`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Token compared with secret using !== equality",
      context: srcCtx(`if (token !== process.env.SECRET_TOKEN) {
  throw new Error('Invalid token');
}`),
      expect_finding: true,
      kind: "true_positive",
    },
    {
      description: "Safe: crypto.timingSafeEqual() for constant-time comparison",
      context: srcCtx(`const a = Buffer.from(provided);
const b = Buffer.from(expected);
if (crypto.timingSafeEqual(a, b)) allowAccess();`),
      expect_finding: false,
      kind: "true_negative",
    },
    {
      description: "Safe: hmac.compare_digest() in Python",
      context: srcCtx(`import hmac
if hmac.compare_digest(expected_mac, provided_mac):
    authenticate()`),
      expect_finding: false,
      kind: "true_negative",
    },
  ],
};

export const ALL_C_FIXTURES: RuleFixtureSet[] = [
  C1, C2, C3, C4, C5, C6, C7, C8, C9, C10, C11, C12, C13, C14, C15, C16,
];
