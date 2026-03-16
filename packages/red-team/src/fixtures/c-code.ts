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

export const ALL_C_FIXTURES: RuleFixtureSet[] = [C1, C2, C4, C5, C10, C12, C14, C16];
