import { readFileSync, readdirSync } from "fs";
import { join } from "path";
import { parse as parseYaml } from "yaml";
import { DetectionRuleSchema, type DetectionRule } from "@mcp-sentinel/database";
import pino from "pino";

const logger = pino({ name: "analyzer:rule-loader" });

export function loadRules(rulesDir: string): DetectionRule[] {
  const rules: DetectionRule[] = [];
  const files = readdirSync(rulesDir).filter((f) => f.endsWith(".yaml") || f.endsWith(".yml"));

  for (const file of files) {
    try {
      const content = readFileSync(join(rulesDir, file), "utf-8");
      const raw = parseYaml(content);
      const rule = DetectionRuleSchema.parse(raw);

      if (rule.enabled) {
        rules.push(rule);
        logger.debug({ rule: rule.id, name: rule.name }, "Loaded rule");
      }
    } catch (err) {
      logger.error({ file, err }, "Failed to load rule");
    }
  }

  logger.info({ count: rules.length }, "Rules loaded");
  return rules;
}

export function getRulesVersion(rules: DetectionRule[]): string {
  // Version based on rule count and IDs for change detection
  const ids = rules.map((r) => r.id).sort().join(",");
  const hash = simpleHash(ids);
  return `1.0.0-${rules.length}r-${hash}`;
}

function simpleHash(str: string): string {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash + char) | 0;
  }
  return Math.abs(hash).toString(36).substring(0, 6);
}
