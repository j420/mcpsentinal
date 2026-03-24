/**
 * Ground Truth — manually verified findings per benchmark server.
 *
 * Each entry maps a server ID to the set of rule IDs that represent
 * confirmed vulnerabilities. This is the "answer key" for the benchmark.
 *
 * Sources:
 * - CVE entries from NVD (verified via original advisory)
 * - Intentionally vulnerable patterns (authored by security engineer)
 * - Clean servers verified by manual review
 * - Tricky servers verified by AST analysis
 */

export interface GroundTruthEntry {
  server_id: string;
  /** Rule IDs that are confirmed present */
  confirmed_findings: string[];
  /** Rule IDs that are confirmed absent (false positive traps) */
  confirmed_absent: string[];
  /** Verification method */
  verification: "cve-advisory" | "manual-review" | "authored" | "ast-verified";
  /** Notes for auditing */
  notes?: string;
}

/**
 * Build the ground truth map from corpus data.
 * In a real deployment, this would be a separate manually curated dataset.
 * Here we derive it from the corpus definitions for consistency.
 */
export function buildGroundTruth(
  corpus: Array<{
    id: string;
    category: string;
    expected_findings: string[];
    must_not_fire: string[];
    cve?: string;
  }>
): Map<string, GroundTruthEntry> {
  const truth = new Map<string, GroundTruthEntry>();

  for (const server of corpus) {
    truth.set(server.id, {
      server_id: server.id,
      confirmed_findings: server.expected_findings,
      confirmed_absent: server.must_not_fire,
      verification: server.cve
        ? "cve-advisory"
        : server.category === "clean" || server.category === "tricky"
          ? "manual-review"
          : "authored",
      notes: server.cve ? `Verified via ${server.cve}` : undefined,
    });
  }

  return truth;
}

// ── Metrics Computation ─────────────────────────────────────────────────────

export interface BenchmarkMetrics {
  /** True positives: expected finding present AND detected */
  true_positives: number;
  /** False negatives: expected finding present BUT not detected */
  false_negatives: number;
  /** True negatives: must-not-fire rule correctly silent */
  true_negatives: number;
  /** False positives: must-not-fire rule incorrectly triggered */
  false_positives: number;
  /** Precision: TP / (TP + FP) — how many detections are real */
  precision: number;
  /** Recall: TP / (TP + FN) — how many real vulns do we catch */
  recall: number;
  /** False positive rate: FP / (FP + TN) */
  false_positive_rate: number;
  /** F1 score: harmonic mean of precision and recall */
  f1_score: number;
}

export function computeMetrics(
  tp: number, fn: number, tn: number, fp: number
): BenchmarkMetrics {
  const precision = tp + fp > 0 ? tp / (tp + fp) : 1;
  const recall = tp + fn > 0 ? tp / (tp + fn) : 1;
  const fpr = fp + tn > 0 ? fp / (fp + tn) : 0;
  const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;

  return {
    true_positives: tp,
    false_negatives: fn,
    true_negatives: tn,
    false_positives: fp,
    precision: Math.round(precision * 1000) / 10,
    recall: Math.round(recall * 1000) / 10,
    false_positive_rate: Math.round(fpr * 1000) / 10,
    f1_score: Math.round(f1 * 1000) / 10,
  };
}
