# Sprint 2: Audit & Logging — Migrate Rules from YAML Regex to TypeScript

## Mission

You are the **P8 Detection Rule Engineer**. Migrate the **Audit & Logging** risk domain rules from YAML regex to TypeScript. This domain maps to **EU AI Act Article 12 (Record-keeping)** — enforcement deadline August 2, 2026.

**Shared context (AnalysisContext, TypedRule interface, existing toolkits, registration pattern):** See `docs/migration-prompts/sprint-1-human-oversight.md`.

## Rules to Migrate

### Rule K2 — Audit Trail Destruction (PURE REGEX → TypeScript)

**Current YAML:** `rules/K2-audit-trail-destruction.yaml`
**Severity:** critical | **OWASP:** MCP09 | **MITRE:** AML.T0054

**Current regex patterns being replaced:**
```
(unlink|rm|remove|delete).*\b(log|audit|trace|event)[_\s-]?(file|path|dir)
(truncate|empty|clear|purge).*\b(log|audit|trace|event)[_\s-]?(file|path)
writeFile(?:Sync)?\s*\(.*(?:log|audit).*["']\s*["']
os\.(?:remove|unlink)\s*\(.*(?:log|audit)
shutil\.rmtree\s*\(.*(?:log|audit)
```

**Analysis technique:** Source code pattern matching with context awareness:
1. Find file-deletion calls (`fs.unlink`, `fs.unlinkSync`, `os.remove`, `os.unlink`, `shutil.rmtree`, `fs.rm`, `fs.rmSync`)
2. Check if the argument references a log/audit path (string contains `log`, `audit`, `trace`, `event` combined with `file`, `path`, `dir`)
3. Find truncation patterns: `writeFileSync(logPath, '')`, `open(logPath, 'w')`, `truncate()`
4. Exclude log rotation: skip if surrounding context contains `rotate`, `archive`, `compress`, `backup`, `retention`, `gzip`, `zip`
5. Exclude test files: skip if path or content matches `test|spec|mock|fixture`

**Confidence model:**
- Delete/unlink call with literal `audit` or `log` in argument → 0.90
- Truncation/overwrite of log file → 0.85
- Generic delete where variable name suggests log path → 0.65
- Regex fallback only → 0.50

**Test cases (4 TP + 4 TN):**

```typescript
// TP1: Direct audit log deletion
const tp1 = `
import fs from 'fs';
function cleanupAfterExfil(logDir: string) {
  fs.unlinkSync(logDir + '/audit.log');
  fs.unlinkSync(logDir + '/access.log');
}`;

// TP2: Python os.remove on audit trail
const tp2 = `
import os
def destroy_evidence(log_path):
    os.remove(log_path + '/audit_trail.log')
    os.remove(log_path + '/event_log.json')`;

// TP3: Truncating log file by overwriting with empty string
const tp3 = `
const fs = require('fs');
function clearLogs() {
  fs.writeFileSync('/var/log/mcp-server/audit.log', '');
}`;

// TP4: shutil.rmtree on entire log directory
const tp4 = `
import shutil
def cleanup():
    shutil.rmtree('/var/log/audit/')`;

// TN1: Log rotation with archive (should NOT flag)
const tn1 = `
import fs from 'fs';
function rotateLogs(logPath: string) {
  const archivePath = logPath + '.gz';
  compressFile(logPath, archivePath);
  fs.unlinkSync(logPath);  // delete after archiving
}`;

// TN2: Test file cleanup (should NOT flag)
const tn2 = `
// test/cleanup.test.ts
afterEach(() => {
  fs.unlinkSync(tmpDir + '/test-audit.log');
});`;

// TN3: Deleting non-log files (should NOT flag)
const tn3 = `
import fs from 'fs';
function cleanup(uploadDir: string) {
  fs.unlinkSync(uploadDir + '/temp-image.png');
}`;

// TN4: Log backup/retention policy (should NOT flag)
const tn4 = `
import fs from 'fs';
function enforceRetention(logDir: string, maxAgeDays: number) {
  const files = fs.readdirSync(logDir);
  for (const f of files) {
    if (isOlderThan(f, maxAgeDays)) {
      archiveToS3(f);
      fs.unlinkSync(path.join(logDir, f)); // delete after backup
    }
  }
}`;
```

---

### Rule K3 — Audit Log Tampering (PURE REGEX → TypeScript)

**Current YAML:** `rules/K3-audit-log-tampering.yaml`
**Severity:** critical | **OWASP:** MCP09 | **MITRE:** AML.T0054

**Current regex patterns being replaced:**
```
readFile(?:Sync)?\s*\(.*(?:log|audit).*(?:replace|split|filter|map).*writeFile
(?:log|audit)[_\s-]?(?:file|path).*(?:sed|awk|perl).*-i
(?:fake|forge|spoof|fabricate)[_\s-]?(?:log|timestamp|entry|record)
open\s*\(.*(?:log|audit).*["']r\+["']
```

**Analysis technique:** Detect read-modify-write patterns on log files:
1. Find file reads targeting log/audit files followed by content transformation (filter, replace, map, split) followed by file write
2. Detect `open(logPath, 'r+')` — opening log files in read-write mode (enables in-place modification)
3. Detect `sed -i` or `awk` commands targeting log files
4. Detect forged timestamp/entry patterns: variable names with `fake`, `forge`, `spoof` + `log`, `timestamp`
5. Exclude PII redaction at write time: skip if context contains `redact`, `sanitize`, `mask`, `pii`, `gdpr`

**Confidence model:**
- readFile→filter/replace→writeFile chain on audit file → 0.92
- open() in r+ mode on log/audit file → 0.85
- sed -i on log file → 0.88
- Forged timestamp variable names → 0.70

**Test cases (4 TP + 4 TN):**

```typescript
// TP1: Read-filter-write pattern on audit log
const tp1 = `
import fs from 'fs';
function hideEvidence(logPath: string, toolCallId: string) {
  const content = fs.readFileSync(logPath + '/audit.log', 'utf8');
  const filtered = content.split('\\n').filter(l => !l.includes(toolCallId)).join('\\n');
  fs.writeFileSync(logPath + '/audit.log', filtered);
}`;

// TP2: Python open in r+ mode to overwrite log entries
const tp2 = `
def tamper_log(log_path):
    with open(log_path + '/audit.log', 'r+') as f:
        content = f.read()
        f.seek(0)
        f.write(content.replace('EXFILTRATE', 'NORMAL'))
        f.truncate()`;

// TP3: sed -i to modify log entries in-place
const tp3 = `
const { execSync } = require('child_process');
function coverTracks(logFile: string) {
  execSync(\`sed -i '/malicious_tool/d' \${logFile}\`);
}`;

// TP4: Forging fake timestamps in log entries
const tp4 = `
function injectFakeLogEntry(logPath: string) {
  const forgedTimestamp = new Date(Date.now() - 86400000).toISOString();
  const fakeEntry = \`\${forgedTimestamp} INFO Normal operation completed\`;
  fs.appendFileSync(logPath, fakeEntry + '\\n');
}`;

// TN1: PII redaction at write time (should NOT flag)
const tn1 = `
import pino from 'pino';
const logger = pino({
  redact: ['req.headers.authorization', 'req.body.password'],
});
logger.info({ req }, 'Tool call received');`;

// TN2: Reading logs for monitoring/alerting (should NOT flag)
const tn2 = `
function checkLogForErrors(logPath: string) {
  const content = fs.readFileSync(logPath, 'utf8');
  const errors = content.split('\\n').filter(l => l.includes('ERROR'));
  if (errors.length > 10) alertOps(errors);
}`;

// TN3: Test file verifying log output (should NOT flag)
const tn3 = `
// test/logging.test.ts
it('writes structured log entries', () => {
  const logContent = fs.readFileSync(testLogPath, 'utf8');
  expect(logContent).toContain('toolName');
});`;

// TN4: GDPR-compliant data masking in logger config (should NOT flag)
const tn4 = `
const logger = winston.createLogger({
  format: winston.format.combine(
    maskSensitiveFields(['email', 'phone', 'ssn']),
    winston.format.json()
  )
});`;
```

---

### Rule K20 — Insufficient Audit Context (PURE REGEX → TypeScript)

**Current YAML:** `rules/K20-insufficient-audit-context.yaml`
**Severity:** medium | **OWASP:** MCP09 | **MITRE:** AML.T0054

**Current regex patterns being replaced:**
```
console\.(log|warn|error)\s*\(\s*["'`](?:request|handling|processing|executing|tool|invoke)
logger\.(info|warn|error)\s*\(\s*["'`][^"'`]+["'`]\s*\)\s*;?\s*$
print\s*\(.*(?:request|handle|process|tool|invoke|execute)
logger\.(info|warn|error)\s*\(.*(?:tool|request|handle|invoke)(?!.*(?:requestId|correlationId|traceId))
```

**Analysis technique:** Detect logging calls that lack structured context fields:
1. Find `console.log/warn/error` used for request/tool handling (not structured, not persistent)
2. Find `logger.info/warn/error(stringOnly)` — logger called with only a message string, no object fields
3. Find `print()` in Python handling tool/request operations
4. Check for ABSENCE of structured fields: `requestId`, `correlationId`, `traceId`, `toolName`, `agentId`, `userId`
5. Exclude when structured logger IS used correctly: `logger.info({ requestId, toolName }, msg)`

**Confidence model:**
- `console.log` for tool/request handling → 0.80
- `logger.info(stringOnly)` in handler context → 0.75
- `print()` for tool handling in Python → 0.80
- Logger call near handler but missing specific fields → 0.60

**Test cases (4 TP + 4 TN):**

```typescript
// TP1: console.log for tool request handling
const tp1 = `
async function handleToolCall(req: Request) {
  console.log('handling tool request: ' + req.body.tool);
  const result = await executeTool(req.body.tool, req.body.params);
  console.log('tool execution complete');
  return result;
}`;

// TP2: Logger with string-only message, no structured fields
const tp2 = `
import pino from 'pino';
const logger = pino();
server.tool('delete-file', async (params) => {
  logger.info('Tool invoked: delete-file');
  await fs.unlink(params.path);
  logger.info('File deleted successfully');
});`;

// TP3: Python print() for tool execution logging
const tp3 = `
@mcp.tool()
def execute_query(query: str):
    print(f"Executing tool: execute_query with query={query}")
    result = db.execute(query)
    print("Query executed successfully")
    return result`;

// TP4: Logger missing correlation ID in request handler
const tp4 = `
app.post('/tools/invoke', (req, res) => {
  logger.info('Tool invocation request received');
  logger.info('Processing tool: ' + req.body.toolName);
  // no requestId, no agentId, no traceId
  const result = invokeToolHandler(req.body);
  logger.info('Tool completed');
  res.json(result);
});`;

// TN1: Structured pino logging with all required fields (should NOT flag)
const tn1 = `
import pino from 'pino';
const logger = pino();
server.tool('delete-file', async (params, { requestId, agentId }) => {
  logger.info({ requestId, agentId, toolName: 'delete-file', params: sanitize(params) },
    'Tool invoked');
  await fs.unlink(params.path);
  logger.info({ requestId, agentId, toolName: 'delete-file', status: 'success', durationMs: elapsed },
    'Tool completed');
});`;

// TN2: Test file using console.log (should NOT flag)
const tn2 = `
// __tests__/tools.test.ts
it('handles tool call', async () => {
  console.log('Running test for tool call handler');
  const result = await handler({ tool: 'test-tool' });
  expect(result).toBeDefined();
});`;

// TN3: Winston with structured fields (should NOT flag)
const tn3 = `
const logger = winston.createLogger({ format: winston.format.json() });
server.tool('read-file', async (params) => {
  logger.info('Tool invoked', {
    toolName: 'read-file',
    requestId: ctx.requestId,
    agentId: ctx.agentId,
    timestamp: new Date().toISOString()
  });
});`;

// TN4: Debug console.log not in request handler (should NOT flag)
const tn4 = `
// startup.ts
console.log('MCP server starting on port ' + port);
console.log('Loaded ' + tools.length + ' tools');`;
```

---

### Rule K1 — Absent Structured Logging (ENGINE CLEANUP — remove regex fallback)

**Current YAML:** `rules/K1-absent-structured-logging.yaml`
**Status:** CodeAnalyzer already handles this via `detectK1AbsentStructuredLogging()` at line 1262 of `packages/analyzer/src/engines/code-analyzer.ts`.

**Action:**
1. Verify CodeAnalyzer handles K1: `grep -n "K1\|detectK1" packages/analyzer/src/engines/code-analyzer.ts`
2. Update YAML `detect.type` from `regex` to `typed`
3. Remove `patterns`, `context`, `exclude_patterns` fields from YAML
4. Keep all metadata (id, severity, owasp, mitre, frameworks, remediation, test_cases)

---

## Files to Create/Modify

| File | Action |
|------|--------|
| `packages/analyzer/src/rules/implementations/k2-audit-trail-destruction.ts` | **Create** — TypedRule |
| `packages/analyzer/src/rules/implementations/k3-audit-log-tampering.ts` | **Create** — TypedRule |
| `packages/analyzer/src/rules/implementations/k20-insufficient-audit-context.ts` | **Create** — TypedRule |
| `packages/analyzer/src/rules/index.ts` | **Modify** — add 3 imports |
| `packages/analyzer/__tests__/rules/k2-audit-destruction.test.ts` | **Create** — 8 test cases |
| `packages/analyzer/__tests__/rules/k3-audit-tampering.test.ts` | **Create** — 8 test cases |
| `packages/analyzer/__tests__/rules/k20-insufficient-audit.test.ts` | **Create** — 8 test cases |
| `rules/K2-audit-trail-destruction.yaml` | **Modify** — `type: regex` → `type: typed`, remove patterns |
| `rules/K3-audit-log-tampering.yaml` | **Modify** — `type: regex` → `type: typed`, remove patterns |
| `rules/K20-insufficient-audit-context.yaml` | **Modify** — `type: regex` → `type: typed`, remove patterns |
| `rules/K1-absent-structured-logging.yaml` | **Modify** — `type: regex` → `type: typed`, remove patterns |

## Verification

1. `pnpm typecheck` — all packages pass
2. `pnpm test --filter=@mcp-sentinel/analyzer` — all tests pass including new K2/K3/K20 tests
3. `bash tools/scripts/validate-rules.sh` — all 177 rules validate
4. K1/K2/K3/K20 YAML files no longer contain `patterns` or `context` fields
5. K2/K3/K20 TypedRules produce findings with confidence scores and evidence
