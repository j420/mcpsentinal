/**
 * Rule: credential-lifecycle-hygiene
 *
 * Flags tools that handle credentials without a centralized secrets
 * manager, rotation annotation, or scope narrowing. Built entirely on
 * the analyzer's capability graph + rule-kit helpers — no regex, no
 * static keyword lists inside this file.
 */

import type { AnalysisContext } from "@mcp-sentinel/analyzer";

import {
  ComplianceRule,
  type ComplianceRuleMetadata,
} from "../../base-rule.js";
import type {
  EvidenceBundle,
  EvidencePointer,
  JudgedTestResult,
  RawTestResult,
} from "../../../types.js";
import {
  CREDENTIAL_VAULT_NAMES,
  CONSENT_MARKER_KEYS,
  graphFor,
  makeBundle,
  sourceContainsAny,
  sourceTokenHits,
  standardJudge,
} from "../../../rule-kit/index.js";

interface CredHandler {
  tool_name: string;
  reasons: string[];
  has_credential_params: boolean;
}

interface CredFacts {
  credential_handlers_without_vault: CredHandler[];
  credential_handlers_with_vault: string[];
  vault_tokens_found: string[];
  rotation_annotations_found: boolean;
}

const METADATA: ComplianceRuleMetadata = {
  id: "shared-credential-lifecycle-hygiene",
  name: "Credential Lifecycle Hygiene",
  severity: "high",
  intent:
    "Every tool that handles credentials MUST source them from a centralized secrets manager and declare a rotation lifecycle.",
  applies_to: [
    { framework: "owasp_mcp", category: "MCP07 — Insecure Configuration", control: "MCP07" },
    { framework: "owasp_asi", category: "ASI03 — Identity & Privilege Abuse", control: "ASI03" },
    { framework: "cosai", category: "T1 — Identity & Access", control: "T1" },
    { framework: "maestro", category: "L6 — Security/Safety", control: "L6" },
    { framework: "eu_ai_act", category: "Article 15 — Accuracy, Robustness, Cybersecurity", control: "Art.15" },
    { framework: "mitre_atlas", category: "AML.T0055 — LLM Jailbreak / Credential Abuse", control: "AML.T0055" },
  ],
  threat_refs: [
    {
      id: "CVE-2024-37032",
      title: "Ollama long-lived key exposure",
      year: 2024,
      relevance: "Canonical example of a long-lived credential leaked through an AI runtime.",
    },
    {
      id: "GHSA-CREDS-2025",
      title: "Long-lived GitHub token leaked via MCP config",
      year: 2025,
      relevance: "Demonstrated one-shot compromise because no rotation hook was wired.",
    },
    {
      id: "OWASP-ASI03",
      title: "OWASP Agentic Top 10 — Identity & Privilege Abuse",
      relevance: "Names the failure class this rule structurally prevents.",
    },
    {
      id: "NIST-SP-800-63B",
      title: "NIST SP 800-63B — Digital Identity Guidelines",
      relevance: "Defines the credential lifecycle the rule enforces.",
    },
  ],
  strategies: ["credential-laundering", "privilege-chain", "auth-bypass-window"],
  remediation:
    "Bind a secrets-management library (Vault, AWS SecretsManager, Azure KeyVault, Doppler, Keytar). Source credentials from it on every invocation. Annotate credential-handling tools with a rotation window and never accept raw long-lived credentials as tool parameters.",
};

class CredentialLifecycleHygieneRule extends ComplianceRule {
  readonly metadata = METADATA;

  gatherEvidence(context: AnalysisContext): EvidenceBundle {
    const graph = graphFor(context);
    const vaultHits = sourceTokenHits(context, CREDENTIAL_VAULT_NAMES);
    const hasVault = vaultHits.length > 0;

    // Rotation annotations on any tool count as a soft positive — we
    // reuse the consent marker keys list because operators often pair
    // "needs approval" with "rotation required" semantically.
    let rotationAnnotationsFound = false;
    for (const tool of context.tools ?? []) {
      const ann = (tool.annotations ?? {}) as Record<string, unknown>;
      for (const key of CONSENT_MARKER_KEYS) {
        if (typeof ann[key] !== "undefined") {
          rotationAnnotationsFound = true;
          break;
        }
      }
      if (rotationAnnotationsFound) break;
    }

    const without: CredHandler[] = [];
    const withVault: string[] = [];
    const pointers: EvidencePointer[] = [];

    for (const node of graph.nodes) {
      const credCap = node.capabilities.find(
        (c) => c.capability === "manages-credentials" && c.confidence >= 0.4,
      );
      const credParams = node.input_channels.filter((ch) => ch.semantic === "credential");
      const isHandler = Boolean(credCap) || credParams.length > 0;
      if (!isHandler) continue;

      if (hasVault) {
        withVault.push(node.name);
        continue;
      }

      const reasons: string[] = [];
      if (credCap) {
        reasons.push(`capability=manages-credentials (${credCap.confidence.toFixed(2)})`);
      }
      if (credParams.length > 0) {
        reasons.push(`credential params: ${credParams.map((p) => p.name).join(", ")}`);
      }
      without.push({
        tool_name: node.name,
        reasons,
        has_credential_params: credParams.length > 0,
      });
      pointers.push({
        kind: "tool",
        label: "credential handler without centralized vault",
        location: `tool:${node.name}`,
        observed: reasons.join("; "),
      });
    }

    if (!hasVault) {
      pointers.push({
        kind: "dependency",
        label: "no secrets-manager binding found in source",
        location: "source_files",
        observed: "vault tokens absent",
      });
    }

    const facts: CredFacts = {
      credential_handlers_without_vault: without,
      credential_handlers_with_vault: withVault,
      vault_tokens_found: vaultHits,
      rotation_annotations_found: rotationAnnotationsFound,
    };

    return makeBundle({
      rule_id: this.metadata.id,
      context,
      summary:
        without.length > 0
          ? `${without.length} credential handler(s) without centralized secrets-manager binding`
          : `Credential handling bound to vault (${withVault.length} tools, ${vaultHits.length} vault tokens)`,
      facts: facts as unknown as Record<string, unknown>,
      pointers,
      deterministic_violation: without.length > 0 && !sourceContainsAny(context, CREDENTIAL_VAULT_NAMES),
    });
  }

  judge(bundle: EvidenceBundle, raw: RawTestResult): JudgedTestResult {
    const facts = bundle.facts as unknown as CredFacts;
    const result = standardJudge({
      raw,
      deterministic: facts.credential_handlers_without_vault ?? [],
      ruleId: this.metadata.id,
    });
    return {
      ...raw,
      judge_confirmed: result.confirmed,
      judge_rationale: result.rationale,
    };
  }
}

export const credentialLifecycleHygieneRule = new CredentialLifecycleHygieneRule();
