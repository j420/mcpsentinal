/**
 * FrameworkAgent abstract base.
 *
 * A framework agent owns:
 *   1. The framework's metadata (name, authority, reference URL).
 *   2. The category taxonomy (Article 14, MCP01, ASI09, T2, L6, AML.T0054 ...).
 *   3. A lookup from category → rule ids.
 *
 * It does NOT execute rules — that's the orchestrator's job. The agent is
 * the *taxonomy provider* the orchestrator dispatches against and the
 * *report shape* the reporter renders.
 *
 * To add a framework: subclass FrameworkAgent, populate `metadata` and
 * `categoryDefinitions`, and register it in `index.ts`.
 */

import { rulesForFramework } from "../rules/registry.js";
import type {
  FrameworkAgentLike,
  FrameworkCategory,
  FrameworkId,
  FrameworkMetadata,
} from "../types.js";

/**
 * Lightweight category definition the subclass declares. The base class
 * resolves rule_ids dynamically by asking the registry which rules apply
 * to (this framework, this category).
 */
export interface CategoryDefinition {
  /** e.g. "MCP01", "Article 14", "ASI09", "T2", "L6", "AML.T0054" */
  control: string;
  /** e.g. "Prompt Injection", "Article 14 — Human Oversight" */
  name: string;
  /** What the category requires in plain language */
  description: string;
}

export abstract class FrameworkAgent implements FrameworkAgentLike {
  abstract readonly id: FrameworkId;
  abstract readonly metadata: FrameworkMetadata;
  protected abstract readonly categoryDefinitions: CategoryDefinition[];

  categories(): FrameworkCategory[] {
    const ruleSet = rulesForFramework(this.id);
    return this.categoryDefinitions.map((def) => {
      const ruleIds = ruleSet
        .filter((r) =>
          r.metadata.applies_to.some(
            (m) => m.framework === this.id && m.control === def.control,
          ),
        )
        .map((r) => r.metadata.id);
      return {
        name: def.name,
        control: def.control,
        description: def.description,
        rule_ids: ruleIds,
      };
    });
  }

  ruleIds(): string[] {
    const seen = new Set<string>();
    for (const cat of this.categories()) {
      for (const id of cat.rule_ids) {
        seen.add(id);
      }
    }
    return Array.from(seen);
  }
}
