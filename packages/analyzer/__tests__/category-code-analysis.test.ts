/**
 * Category: Code Analysis (C1-C16) — 48 tests
 * Focuses on taint analysis edge cases, multi-language coverage, and false positive reduction.
 */
import { describe, it, expect } from "vitest";
import type { AnalysisContext } from "../src/engine.js";
import { getTypedRule } from "../src/rules/base.js";
import "../src/rules/index.js";

function ctx(src: string): AnalysisContext {
  return { server: { id: "t", name: "test", description: null, github_url: null }, tools: [], source_code: src, dependencies: [], connection_metadata: null };
}
function run(id: string, src: string) { return getTypedRule(id)!.analyze(ctx(src)); }

describe("C1 — Command Injection (Taint)", () => {
  it("flags exec with request body input", () => {
    const f = run("C1", `const cmd = req.body.command;\nexecSync(cmd);`);
    expect(f.some(x => x.rule_id === "C1")).toBe(true);
  });
  it("flags template literal in exec", () => {
    const f = run("C1", "execSync(`git clone ${userUrl}`);");
    expect(f.some(x => x.rule_id === "C1")).toBe(true);
  });
  it("does NOT flag hardcoded exec", () => {
    const f = run("C1", 'execSync("git status");');
    expect(f.filter(x => x.rule_id === "C1" && x.severity === "critical").length).toBe(0);
  });
  it("does NOT flag execFile (safe alternative)", () => {
    const f = run("C1", 'execFileSync("git", ["status"]);');
    expect(f.filter(x => x.rule_id === "C1" && x.severity === "critical").length).toBe(0);
  });
});

describe("C2 — Path Traversal (Taint)", () => {
  it("flags literal ../etc/passwd", () => {
    const f = run("C2", `fs.readFileSync("../../etc/passwd");`);
    expect(f.some(x => x.rule_id === "C2")).toBe(true);
  });
  it("flags URL-encoded traversal", () => {
    const f = run("C2", `fs.readFileSync(path + "%2e%2e/etc/shadow");`);
    expect(f.some(x => x.rule_id === "C2")).toBe(true);
  });
  it("does NOT flag path.resolve with base dir", () => {
    const crit = run("C2", `const safe = path.resolve(baseDir, input);\nfs.readFileSync(safe);`).filter(x => x.severity === "critical");
    expect(crit.length).toBe(0);
  });
});

describe("C3 — SSRF (Taint)", () => {
  it("flags user URL in fetch", () => {
    const f = run("C3", `const url = req.query.url;\nfetch(url);`);
    expect(f.some(x => x.rule_id === "C3")).toBe(true);
  });
  it("does NOT flag hardcoded URL", () => {
    const f = run("C3", `fetch("https://api.example.com/data");`);
    expect(f.filter(x => x.rule_id === "C3" && x.severity === "high").length).toBe(0);
  });
});

describe("C4 — SQL Injection (Taint)", () => {
  it("flags template literal SQL", () => {
    const f = run("C4", "const name = req.body.name;\ndb.query(`SELECT * FROM users WHERE name = '${name}'`);");
    expect(f.some(x => x.rule_id === "C4")).toBe(true);
  });
  it("flags string concat SQL", () => {
    const f = run("C4", `db.query("SELECT * FROM users WHERE id = " + userId);`);
    expect(f.some(x => x.rule_id === "C4")).toBe(true);
  });
  it("flags Python f-string SQL", () => {
    const f = run("C4", `name = request.form['name']\ncursor.execute(f"SELECT * FROM users WHERE name = '{name}'")`);
    expect(f.some(x => x.rule_id === "C4")).toBe(true);
  });
  it("does NOT flag parameterized $1 query", () => {
    const crit = run("C4", `db.query("SELECT * FROM users WHERE id = $1", [userId]);`).filter(x => x.severity === "critical");
    expect(crit.length).toBe(0);
  });
  it("does NOT flag prepared statement", () => {
    const crit = run("C4", `const stmt = db.prepare("SELECT * FROM users WHERE id = ?");\nstmt.run(userId);`).filter(x => x.severity === "critical");
    expect(crit.length).toBe(0);
  });
});

describe("C5 — Hardcoded Secrets (Entropy)", () => {
  it("detects GitHub PAT (ghp_)", () => {
    const f = run("C5", `const token = "ghp_xK9mR2nL5pQ7wY3jH8vB0cF4gA6dE1iU0tZs";`);
    expect(f.some(x => x.rule_id === "C5")).toBe(true); expect(f[0].confidence).toBeGreaterThan(0.95);
  });
  it("detects Stripe secret key", () => {
    const f = run("C5", `const key = "sk_live_ABCDEFGHIJKLMNOPQRSTUVWXyz";`);
    expect(f.some(x => x.rule_id === "C5")).toBe(true);
  });
  it("detects PEM private key", () => {
    const f = run("C5", `const cert = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEpA";`);
    expect(f.some(x => x.rule_id === "C5")).toBe(true);
  });
  it("does NOT flag low-entropy string", () => {
    expect(run("C5", `const x = "aaaaaaaaaaaaaaaaaaaaaa";`).filter(x => x.rule_id === "C5").length).toBe(0);
  });
  it("does NOT flag example/placeholder", () => {
    expect(run("C5", `const key = "test_placeholder_not_real_key";`).filter(x => x.rule_id === "C5").length).toBe(0);
  });
  it("does NOT flag comments", () => {
    expect(run("C5", `// const key = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh";`).filter(x => x.rule_id === "C5").length).toBe(0);
  });
});

describe("C6 — Error Leakage", () => {
  it("flags error stack in response", () => {
    expect(run("C6", `res.json(err.stack);`).some(x => x.rule_id === "C6")).toBe(true);
  });
  it("does NOT flag generic error message", () => {
    expect(run("C6", `res.json({ error: "Something went wrong" });`).filter(x => x.rule_id === "C6").length).toBe(0);
  });
});

describe("C7 — Wildcard CORS", () => {
  it("flags Access-Control-Allow-Origin: *", () => {
    expect(run("C7", `res.setHeader("Access-Control-Allow-Origin", "*");\ncors: "*"`).some(x => x.rule_id === "C7")).toBe(true);
  });
  it("flags cors() with no config", () => {
    expect(run("C7", `app.use(cors());`).some(x => x.rule_id === "C7")).toBe(true);
  });
  it("does NOT flag specific origin", () => {
    expect(run("C7", `app.use(cors({ origin: "https://mysite.com" }));`).filter(x => x.rule_id === "C7").length).toBe(0);
  });
});

describe("C8 — No Auth on Network Interface", () => {
  it("flags 0.0.0.0 without auth", () => {
    expect(run("C8", `server.listen(3000, "0.0.0.0");`).some(x => x.rule_id === "C8")).toBe(true);
  });
  it("does NOT flag when auth middleware present", () => {
    expect(run("C8", `app.use(authenticate);\nserver.listen(3000, "0.0.0.0");`).filter(x => x.rule_id === "C8").length).toBe(0);
  });
});

describe("C9 — Excessive Filesystem Scope", () => {
  it("flags root directory listing", () => {
    expect(run("C9", `fs.readdirSync("/");`).some(x => x.rule_id === "C9")).toBe(true);
  });
  it("flags basePath = /", () => {
    expect(run("C9", `const basePath = "/";`).some(x => x.rule_id === "C9")).toBe(true);
  });
});

describe("C10 — Prototype Pollution", () => {
  it("flags __proto__ access with user input", () => {
    const f = run("C10", `const data = req.body;\nobj.__proto__[data.key] = data.value;`);
    expect(f.some(x => x.rule_id === "C10")).toBe(true);
  });
  it("flags lodash merge with request data", () => {
    expect(run("C10", `const userConfig = req.body.config;\n_.merge(config, userConfig);`).some(x => x.rule_id === "C10")).toBe(true);
  });
  it("does NOT flag Object.create(null)", () => {
    expect(run("C10", `const m = Object.create(null);\nm[k] = v;`).filter(x => x.rule_id === "C10").length).toBe(0);
  });
});

describe("C11 — ReDoS", () => {
  it("flags RegExp from user input", () => {
    expect(run("C11", `new RegExp(userInput)`).some(x => x.rule_id === "C11")).toBe(true);
  });
  it("flags catastrophic backtracking", () => {
    expect(run("C11", `const re = /(a+)+b/;`).some(x => x.rule_id === "C11")).toBe(true);
  });
});

describe("C12 — Unsafe Deserialization", () => {
  it("flags pickle.loads with network data", () => {
    expect(run("C12", `data = request.data\nobj = pickle.loads(data)`).some(x => x.rule_id === "C12")).toBe(true);
  });
  it("flags yaml.load without SafeLoader", () => {
    expect(run("C12", `config = yaml.load(content)`).some(x => x.rule_id === "C12")).toBe(true);
  });
  it("flags node-serialize", () => {
    expect(run("C12", `const serialize = require("node-serialize");`).some(x => x.rule_id === "C12")).toBe(true);
  });
  it("does NOT flag yaml.safe_load", () => {
    expect(run("C12", `config = yaml.safe_load(content)`).filter(x => x.rule_id === "C12" && x.severity === "critical").length).toBe(0);
  });
});

describe("C13 — Template Injection", () => {
  it("flags Jinja2 from_string with variable", () => {
    expect(run("C13", `tmpl = request.form['tmpl']\nEnvironment().from_string(tmpl).render()`).some(x => x.rule_id === "C13")).toBe(true);
  });
  it("flags nunjucks.renderString with variable", () => {
    expect(run("C13", `const tpl = req.body.template;\nnunjucks.renderString(tpl, data);`).some(x => x.rule_id === "C13")).toBe(true);
  });
  it("does NOT flag file-based render", () => {
    expect(run("C13", `res.render("index.html", { user });`).filter(x => x.rule_id === "C13" && x.severity === "critical").length).toBe(0);
  });
});

describe("C14 — JWT Algorithm Confusion", () => {
  it("flags 'none' algorithm", () => {
    expect(run("C14", `jwt.verify(token, key, { algorithms: ['none'] });`).some(x => x.rule_id === "C14")).toBe(true);
  });
  it("flags ignoreExpiration: true", () => {
    expect(run("C14", `jwt.verify(token, key, { ignoreExpiration: true });`).some(x => x.rule_id === "C14")).toBe(true);
  });
  it("flags PyJWT verify=False", () => {
    expect(run("C14", `payload = jwt.decode(token, verify=False)`).some(x => x.rule_id === "C14")).toBe(true);
  });
  it("does NOT flag pinned RS256", () => {
    expect(run("C14", `jwt.verify(token, publicKey, { algorithms: ['RS256'] });`).filter(x => x.rule_id === "C14").length).toBe(0);
  });
});

describe("C15 — Timing Attack", () => {
  it("flags === on API key comparison", () => {
    expect(run("C15", `if (apiKey === req.headers.authorization) { grant(); }`).some(x => x.rule_id === "C15")).toBe(true);
  });
  it("does NOT flag when timingSafeEqual is used", () => {
    expect(run("C15", `if (crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b))) {}`).filter(x => x.rule_id === "C15").length).toBe(0);
  });
});

describe("C16 — Dynamic Code Eval", () => {
  it("flags eval with variable", () => {
    expect(run("C16", `const expr = req.body.expression;\neval(expr);`).some(x => x.rule_id === "C16")).toBe(true);
  });
  it("flags new Function with variable", () => {
    expect(run("C16", `const fn = new Function(userCode);`).some(x => x.rule_id === "C16")).toBe(true);
  });
  it("does NOT flag JSON.parse", () => {
    expect(run("C16", `const data = JSON.parse(body);`).filter(x => x.rule_id === "C16" && x.severity !== "informational").length).toBe(0);
  });
});
