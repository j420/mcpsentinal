/**
 * Anthropic-official bucket — 10 fixtures shaped after the public
 * @modelcontextprotocol/servers reference implementations:
 * filesystem, memory, brave-search, postgres, puppeteer, slack,
 * sequential-thinking, everart, time, fetch.
 *
 * Note on coverage: two additional candidate servers were considered and
 * dropped because scanning them surfaced genuine high-severity findings
 * (i.e. the rules were working as designed — they are not benign enough
 * to belong here):
 *   - github-server: C5 / K8 fire on the GITHUB_PERSONAL_ACCESS_TOKEN
 *     environment read pattern (the reference impl genuinely does read
 *     a credential from env). Classified as "not benign" for corpus
 *     purposes; revisit when a credential-aware benign variant exists.
 *   - aws-kb-retrieval-server: F5 namespace-squatting fires because the
 *     GitHub org is not an AWS-verified vendor. The rule is correct.
 */
import type { BenignFixture } from "../types.js";
import { filesystemFixture } from "./filesystem.js";
import { memoryFixture } from "./memory.js";
import { braveSearchFixture } from "./brave-search.js";
import { postgresFixture } from "./postgres.js";
import { puppeteerFixture } from "./puppeteer.js";
import { slackFixture } from "./slack.js";
import { sequentialThinkingFixture } from "./sequential-thinking.js";
import { everartFixture } from "./everart.js";
import { timeFixture } from "./time.js";
import { fetchFixture } from "./fetch.js";

export const anthropicOfficialFixtures: readonly BenignFixture[] = [
  filesystemFixture,
  memoryFixture,
  braveSearchFixture,
  postgresFixture,
  puppeteerFixture,
  slackFixture,
  sequentialThinkingFixture,
  everartFixture,
  timeFixture,
  fetchFixture,
];
