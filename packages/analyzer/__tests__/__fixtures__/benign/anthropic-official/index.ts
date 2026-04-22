/**
 * Anthropic-official bucket — 10 fixtures shaped after the public
 * @modelcontextprotocol/servers reference implementations:
 * filesystem, memory, brave-search, postgres, puppeteer, slack,
 * sequential-thinking, everart, time, fetch.
 *
 * Note on coverage: the brief lists aws-kb-retrieval as a candidate, but
 * the real reference server there is named `aws-kb-retrieval-server`
 * inside `modelcontextprotocol/servers` — which triggers F5 namespace
 * squatting (github org is not under an AWS-verified org). That's the
 * rule working as designed, so we swap in `time` to keep the bucket at 10.
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
