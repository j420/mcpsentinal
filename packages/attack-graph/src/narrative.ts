/**
 * Narrative & Mitigation Generation — Deterministic, No LLM
 *
 * Generates human-readable attack stories and actionable mitigations
 * from kill chain templates and attack steps. All generation is
 * template-based string composition.
 *
 * Design:
 *   - Each role has a sentence template that fills in server names
 *   - Narratives are composed by joining per-step fragments
 *   - Mitigations are derived by analyzing which step removal
 *     breaks the chain (ordered: chain-breakers first)
 */
import type {
  AttackStep,
  AttackRole,
  KillChainTemplate,
  Mitigation,
} from "./types.js";

// ── Role narrative templates ───────────────────────────────────────────────────

const ROLE_NARRATIVES: Record<AttackRole, (serverName: string) => string> = {
  injection_gateway: (name) =>
    `An attacker sends crafted content to "${name}" (injection gateway), embedding malicious instructions that the AI client will process as legitimate tool output.`,
  pivot: (name) =>
    `The AI client, following the injected instructions, uses "${name}" to transform or relay the attacker's payload to the next stage.`,
  data_source: (name) =>
    `The AI reads sensitive data through "${name}", believing it is fulfilling a legitimate user request crafted by the injected instructions.`,
  executor: (name) =>
    `"${name}" executes the attacker-controlled code or commands, achieving arbitrary execution on the user's system.`,
  exfiltrator: (name) =>
    `The stolen data is sent externally through "${name}" — via webhook, email, or network request — to an attacker-controlled endpoint.`,
  config_writer: (name) =>
    `"${name}" writes to agent configuration files, injecting a malicious MCP server definition that persists across sessions.`,
  memory_writer: (name) =>
    `"${name}" writes poisoned content to shared agent memory (vector store or scratchpad), creating a persistent backdoor that activates on every future memory retrieval.`,
};

// ── Objective descriptions ─────────────────────────────────────────────────────

const OBJECTIVE_DESC: Record<string, string> = {
  data_exfiltration:
    "The attacker's goal is to steal sensitive data (SSH keys, credentials, PII, proprietary code) from the user's system without detection.",
  remote_code_execution:
    "The attacker's goal is to execute arbitrary code on the user's machine, achieving full system compromise.",
  credential_theft:
    "The attacker's goal is to steal authentication credentials (OAuth tokens, API keys, session tokens) for persistent unauthorized access.",
  persistent_backdoor:
    "The attacker's goal is to establish persistence — a backdoor that survives session restarts and continues operating undetected.",
  privilege_escalation:
    "The attacker's goal is to escalate from limited read-only access to full administrative privileges over databases and systems.",
};

/**
 * Get the narrative fragment for a single attack step.
 * Used by engine.ts to populate AttackStep.narrative.
 */
export function getStepNarrative(role: AttackRole, serverName: string): string {
  const fn = ROLE_NARRATIVES[role];
  return fn ? fn(serverName) : `"${serverName}" acts as ${role}.`;
}

// ── Narrative generation ───────────────────────────────────────────────────────

/**
 * Generate a full attack narrative from a kill chain template and steps.
 *
 * The narrative is structured as:
 *   1. Objective statement
 *   2. Precedent reference
 *   3. Per-step narrative fragments (numbered)
 *   4. Impact statement
 */
export function generateNarrative(
  template: KillChainTemplate,
  steps: AttackStep[]
): string {
  const parts: string[] = [];

  // Objective
  const objDesc = OBJECTIVE_DESC[template.objective] ?? `Attack objective: ${template.objective}.`;
  parts.push(objDesc);

  // Precedent
  if (template.precedent) {
    parts.push(`Precedent: ${template.precedent}`);
  }

  // Per-step narrative
  parts.push(""); // blank line before steps
  parts.push("Attack sequence:");
  for (const step of steps) {
    const roleNarrative = ROLE_NARRATIVES[step.role];
    const fragment = roleNarrative
      ? roleNarrative(step.server_name)
      : `Step ${step.ordinal}: "${step.server_name}" acts as ${step.role}.`;
    parts.push(`  ${step.ordinal}. ${fragment}`);
  }

  // Impact
  parts.push("");
  parts.push(
    `This ${steps.length}-step chain involves ${new Set(steps.map((s) => s.server_id)).size} server(s). ` +
    `No individual server is necessarily malicious — the danger emerges from their combination in a single AI client configuration.`
  );

  return parts.join("\n");
}

// ── Mitigation generation ──────────────────────────────────────────────────────

/**
 * Generate actionable mitigations for an attack chain.
 *
 * Strategy:
 *   1. Identify chain-breaking mitigations (removing one link kills the whole chain)
 *   2. Identify risk-reducing mitigations (make the attack harder but don't prevent it)
 *   3. Order: breaks_chain first, then reduces_risk
 *
 * Standard mitigations per role:
 *   - injection_gateway: remove server or add content filtering
 *   - executor: add confirmation for dangerous operations
 *   - exfiltrator: restrict network capabilities
 *   - config_writer: isolate server, restrict filesystem access
 *   - memory_writer: add confirmation for memory writes
 *   - data_source: add auth or restrict scope
 */
export function generateMitigations(
  _template: KillChainTemplate,
  steps: AttackStep[],
): Mitigation[] {
  const mitigations: Mitigation[] = [];
  const seen = new Set<string>();

  for (const step of steps) {
    const key = `${step.server_id}:${step.role}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const roleMitigations = getMitigationsForRole(step, steps);
    mitigations.push(...roleMitigations);
  }

  // Sort: breaks_chain first, then by ordinal of affected steps
  mitigations.sort((a, b) => {
    if (a.effect !== b.effect) {
      return a.effect === "breaks_chain" ? -1 : 1;
    }
    return Math.min(...a.breaks_steps) - Math.min(...b.breaks_steps);
  });

  return mitigations;
}

function getMitigationsForRole(
  step: AttackStep,
  allSteps: AttackStep[]
): Mitigation[] {
  const mitigations: Mitigation[] = [];

  switch (step.role) {
    case "injection_gateway":
      // Removing the injection gateway breaks the entire chain
      mitigations.push({
        action: "remove_server",
        target_server_id: step.server_id,
        target_server_name: step.server_name,
        description:
          `Remove "${step.server_name}" from the configuration. ` +
          `As the injection gateway, removing it eliminates the attacker's entry point.`,
        breaks_steps: allSteps.map((s) => s.ordinal),
        effect: "breaks_chain",
      });
      mitigations.push({
        action: "isolate_server",
        target_server_id: step.server_id,
        target_server_name: step.server_name,
        description:
          `Move "${step.server_name}" to a separate, isolated AI client configuration ` +
          `with no access to sensitive data or network capabilities.`,
        breaks_steps: [step.ordinal],
        effect: "breaks_chain",
      });
      break;

    case "executor":
      mitigations.push({
        action: "add_confirmation",
        target_server_id: step.server_id,
        target_server_name: step.server_name,
        description:
          `Require explicit human confirmation before "${step.server_name}" ` +
          `executes any code or commands. This breaks the automated attack chain.`,
        breaks_steps: [step.ordinal, ...allSteps.filter((s) => s.ordinal > step.ordinal).map((s) => s.ordinal)],
        effect: "breaks_chain",
      });
      break;

    case "exfiltrator":
      mitigations.push({
        action: "restrict_capability",
        target_server_id: step.server_id,
        target_server_name: step.server_name,
        description:
          `Restrict "${step.server_name}" network capabilities to a pre-approved ` +
          `allowlist of domains. This prevents data exfiltration to attacker endpoints.`,
        breaks_steps: [step.ordinal],
        effect: "breaks_chain",
      });
      mitigations.push({
        action: "add_confirmation",
        target_server_id: step.server_id,
        target_server_name: step.server_name,
        description:
          `Require human confirmation before "${step.server_name}" sends any ` +
          `outbound network requests.`,
        breaks_steps: [step.ordinal],
        effect: "reduces_risk",
      });
      break;

    case "config_writer":
      mitigations.push({
        action: "isolate_server",
        target_server_id: step.server_id,
        target_server_name: step.server_name,
        description:
          `Isolate "${step.server_name}" — remove write access to agent config ` +
          `directories (.claude/, .cursor/, ~/.mcp.json).`,
        breaks_steps: [step.ordinal, ...allSteps.filter((s) => s.ordinal > step.ordinal).map((s) => s.ordinal)],
        effect: "breaks_chain",
      });
      break;

    case "memory_writer":
      mitigations.push({
        action: "add_confirmation",
        target_server_id: step.server_id,
        target_server_name: step.server_name,
        description:
          `Require human confirmation before "${step.server_name}" writes ` +
          `to shared memory or vector stores. This prevents persistent backdoors.`,
        breaks_steps: [step.ordinal, ...allSteps.filter((s) => s.ordinal > step.ordinal).map((s) => s.ordinal)],
        effect: "breaks_chain",
      });
      break;

    case "data_source":
      mitigations.push({
        action: "add_auth",
        target_server_id: step.server_id,
        target_server_name: step.server_name,
        description:
          `Add authentication and scope restrictions to "${step.server_name}". ` +
          `Limit accessible paths/resources to only what is needed.`,
        breaks_steps: [step.ordinal],
        effect: "reduces_risk",
      });
      break;

    case "pivot":
      mitigations.push({
        action: "add_confirmation",
        target_server_id: step.server_id,
        target_server_name: step.server_name,
        description:
          `Add confirmation prompts on "${step.server_name}" for operations ` +
          `that transform or relay data between tools.`,
        breaks_steps: [step.ordinal],
        effect: "reduces_risk",
      });
      break;
  }

  return mitigations;
}
