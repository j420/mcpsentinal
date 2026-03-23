/**
 * Information-Theoretic Analysis Toolkit
 *
 * Detects obfuscated, encoded, or encrypted content using mathematical properties
 * that are invariant to the specific encoding scheme. Unlike regex patterns that
 * match known encodings (base64, hex), entropy analysis catches NOVEL encodings
 * and steganographic payloads that no pattern can anticipate.
 *
 * Techniques:
 * 1. Shannon Entropy — bits per character (randomness measure)
 * 2. Chi-Squared Uniformity — deviation from uniform byte distribution
 * 3. Compression Ratio — Kolmogorov complexity approximation via zlib
 * 4. Byte Frequency Distribution — histogram analysis for encoding detection
 * 5. Sliding Window Entropy — detects embedded high-entropy regions in normal text
 *
 * Reference entropy ranges (empirically measured):
 *   Natural language (English):  3.0–4.5 bits/char
 *   Source code (JS/Python):     4.0–5.5 bits/char
 *   Base64 encoded data:         5.7–6.0 bits/char
 *   Hex encoded data:            3.5–4.0 bits/char
 *   URL-encoded data:            4.5–5.5 bits/char
 *   Encrypted/random data:       7.5–8.0 bits/char
 *   Compressed data:             7.0–7.8 bits/char
 */

import { deflateSync } from "zlib";

/** Result of entropy analysis on a text segment */
export interface EntropyResult {
  /** Shannon entropy in bits per character (0.0–8.0 for byte data) */
  shannon_entropy: number;

  /** Chi-squared statistic measuring deviation from uniform distribution.
   *  Lower = more uniform (likely encrypted/compressed).
   *  Expected value for truly random data: ~255 (df=255). */
  chi_squared: number;

  /** p-value from chi-squared test. <0.05 = significantly non-uniform. */
  chi_squared_p_value: number;

  /** Ratio of compressed size to original size (0.0–1.0+).
   *  Near 1.0 = already compressed/encrypted (incompressible).
   *  Near 0.0 = highly redundant (natural text). */
  compression_ratio: number;

  /** Estimated content classification based on combined metrics */
  classification: EntropyClassification;

  /** Confidence in classification (0.0–1.0) */
  confidence: number;

  /** Byte frequency distribution (256 buckets, normalized to 0.0–1.0) */
  byte_frequencies: Float64Array;
}

export type EntropyClassification =
  | "natural_language"
  | "source_code"
  | "base64"
  | "hex_encoded"
  | "url_encoded"
  | "encrypted_or_random"
  | "compressed"
  | "mixed"
  | "unknown";

/** Result from sliding window entropy analysis */
export interface EntropyAnomaly {
  /** Byte offset where the anomaly starts */
  offset: number;
  /** Length of the anomalous region */
  length: number;
  /** Shannon entropy of the anomalous region */
  entropy: number;
  /** Classification of the anomalous region */
  classification: EntropyClassification;
  /** The anomalous text itself */
  text: string;
  /** Confidence score */
  confidence: number;
}

/**
 * Compute Shannon entropy of a string.
 * H(X) = -Σ p(x) log₂(p(x)) for each unique character x.
 *
 * Returns bits per character (0.0 for constant string, up to log₂(alphabet_size) for uniform).
 */
export function shannonEntropy(text: string): number {
  if (text.length === 0) return 0;

  const freq = new Map<number, number>();
  for (let i = 0; i < text.length; i++) {
    const cp = text.charCodeAt(i);
    freq.set(cp, (freq.get(cp) || 0) + 1);
  }

  let entropy = 0;
  const len = text.length;
  for (const count of freq.values()) {
    const p = count / len;
    if (p > 0) {
      entropy -= p * Math.log2(p);
    }
  }

  return entropy;
}

/**
 * Compute byte frequency distribution normalized to probabilities.
 * Returns a 256-element Float64Array where each element is the
 * probability of that byte value occurring.
 */
export function byteFrequencies(data: Buffer | string): Float64Array {
  const buf = typeof data === "string" ? Buffer.from(data, "utf-8") : data;
  const freq = new Float64Array(256);

  if (buf.length === 0) return freq;

  for (let i = 0; i < buf.length; i++) {
    freq[buf[i]]++;
  }

  // Normalize to probabilities
  for (let i = 0; i < 256; i++) {
    freq[i] /= buf.length;
  }

  return freq;
}

/**
 * Chi-squared goodness-of-fit test against uniform distribution.
 *
 * Tests null hypothesis H₀: bytes are uniformly distributed.
 * χ² = Σ (observed - expected)² / expected
 *
 * For truly random data with 256 possible values:
 *   Expected frequency per byte = n/256
 *   df = 255
 *   Expected χ² ≈ 255 (mean of chi-squared distribution)
 *
 * Returns { statistic, p_value }
 * High p-value (>0.05) → consistent with randomness
 * Low p-value (<0.05) → significantly non-uniform (structured data)
 */
export function chiSquaredUniformity(data: Buffer | string): {
  statistic: number;
  p_value: number;
} {
  const buf = typeof data === "string" ? Buffer.from(data, "utf-8") : data;

  if (buf.length < 16) {
    return { statistic: 0, p_value: 1.0 };
  }

  const counts = new Float64Array(256);
  for (let i = 0; i < buf.length; i++) {
    counts[buf[i]]++;
  }

  const expected = buf.length / 256;
  let chiSq = 0;
  for (let i = 0; i < 256; i++) {
    const diff = counts[i] - expected;
    chiSq += (diff * diff) / expected;
  }

  // Approximate p-value using Wilson-Hilferty transformation
  // For df=255, this is accurate to ~3 decimal places
  const df = 255;
  const z =
    Math.pow(chiSq / df, 1 / 3) -
    (1 - 2 / (9 * df));
  const se = Math.sqrt(2 / (9 * df));
  const zScore = z / se;

  // Standard normal CDF approximation (Abramowitz & Stegun 26.2.17)
  const p_value = 1 - normalCDF(zScore);

  return { statistic: chiSq, p_value };
}

/**
 * Standard normal CDF approximation.
 * Uses Abramowitz & Stegun formula 26.2.17 with maximum error < 7.5e-8.
 */
function normalCDF(z: number): number {
  if (z < -8) return 0;
  if (z > 8) return 1;

  const sign = z < 0 ? -1 : 1;
  z = Math.abs(z);

  const b1 = 0.319381530;
  const b2 = -0.356563782;
  const b3 = 1.781477937;
  const b4 = -1.821255978;
  const b5 = 1.330274429;
  const p = 0.2316419;

  const t = 1.0 / (1.0 + p * z);
  const t2 = t * t;
  const t3 = t2 * t;
  const t4 = t3 * t;
  const t5 = t4 * t;

  const pdf = Math.exp(-0.5 * z * z) / Math.sqrt(2 * Math.PI);
  const cdf = 1 - pdf * (b1 * t + b2 * t2 + b3 * t3 + b4 * t4 + b5 * t5);

  return sign === 1 ? cdf : 1 - cdf;
}

/**
 * Compute compression ratio using zlib deflate.
 * Approximates Kolmogorov complexity: truly random data is incompressible,
 * structured data compresses well.
 *
 * Returns compressed_size / original_size (0.0–1.0+)
 */
export function compressionRatio(text: string): number {
  if (text.length === 0) return 0;

  const buf = Buffer.from(text, "utf-8");
  const compressed = deflateSync(buf, { level: 9 });

  return compressed.length / buf.length;
}

/**
 * Classify content based on combined entropy metrics.
 * Uses a decision tree trained on empirical measurements of known content types.
 */
export function classifyContent(text: string): EntropyResult {
  const entropy = shannonEntropy(text);
  const buf = Buffer.from(text, "utf-8");
  const freq = byteFrequencies(buf);
  const chiSq = chiSquaredUniformity(buf);
  const compRatio = compressionRatio(text);

  // Feature extraction for classification
  const printableRatio = countPrintable(text) / text.length;
  const alphanumRatio = countAlphaNum(text) / text.length;
  const base64Ratio = countBase64Chars(text) / text.length;
  const hexRatio = countHexChars(text) / text.length;
  const urlEncodedCount = (text.match(/%[0-9A-Fa-f]{2}/g) || []).length;
  const urlEncodedRatio = (urlEncodedCount * 3) / text.length;

  let classification: EntropyClassification;
  let confidence: number;

  // Decision tree based on empirical thresholds
  if (entropy >= 7.5 && compRatio > 0.9 && chiSq.p_value > 0.05) {
    // High entropy + incompressible + uniform distribution = encrypted/random
    classification = "encrypted_or_random";
    confidence = Math.min(0.95, 0.7 + chiSq.p_value * 0.25);
  } else if (entropy >= 7.0 && compRatio > 0.85) {
    // High entropy + mostly incompressible = compressed data
    classification = "compressed";
    confidence = 0.7 + (compRatio - 0.85) * 2;
  } else if (
    entropy >= 5.7 &&
    entropy <= 6.1 &&
    base64Ratio > 0.9 &&
    printableRatio > 0.99
  ) {
    // Narrow entropy band + base64 charset dominance = base64
    classification = "base64";
    confidence = 0.85 + (base64Ratio - 0.9) * 1.5;
  } else if (
    entropy >= 3.3 &&
    entropy <= 4.2 &&
    hexRatio > 0.9 &&
    printableRatio > 0.99
  ) {
    // Low-ish entropy + hex charset = hex encoded
    classification = "hex_encoded";
    confidence = 0.8 + (hexRatio - 0.9) * 2;
  } else if (urlEncodedRatio > 0.15) {
    // Significant URL encoding present
    classification = "url_encoded";
    confidence = Math.min(0.9, 0.6 + urlEncodedRatio);
  } else if (entropy < 4.5 && compRatio < 0.5 && printableRatio > 0.95) {
    // Low entropy + compressible + printable = natural language
    classification = "natural_language";
    confidence = 0.75 + (0.5 - compRatio) * 0.5;
  } else if (
    entropy >= 4.0 &&
    entropy <= 5.8 &&
    printableRatio > 0.9 &&
    compRatio < 0.7
  ) {
    // Medium entropy + printable + somewhat compressible = source code
    classification = "source_code";
    confidence = 0.6;
  } else if (entropy >= 5.5 && entropy < 7.5) {
    // High-ish entropy but not matching specific patterns
    classification = "mixed";
    confidence = 0.4;
  } else {
    classification = "unknown";
    confidence = 0.3;
  }

  return {
    shannon_entropy: entropy,
    chi_squared: chiSq.statistic,
    chi_squared_p_value: chiSq.p_value,
    compression_ratio: compRatio,
    classification,
    confidence: Math.min(1.0, Math.max(0.0, confidence)),
    byte_frequencies: freq,
  };
}

/**
 * Sliding window entropy analysis.
 * Scans text with a moving window to detect embedded high-entropy regions
 * within otherwise normal content.
 *
 * This catches injection payloads hidden inside long tool descriptions:
 * "This tool reads files from disk. <base64_encoded_injection_payload>. It supports JSON."
 *
 * The normal description has entropy ~4.0, the embedded payload has entropy ~5.9.
 * The window detects the entropy spike.
 *
 * @param text Input text to analyze
 * @param windowSize Characters per window (default 64)
 * @param stepSize Characters to advance per step (default 16)
 * @param entropyThreshold Minimum entropy to flag (default 5.5)
 */
export function slidingWindowEntropy(
  text: string,
  windowSize = 64,
  stepSize = 16,
  entropyThreshold = 5.5
): EntropyAnomaly[] {
  if (text.length < windowSize) return [];

  const anomalies: EntropyAnomaly[] = [];
  let inAnomaly = false;
  let anomalyStart = 0;

  for (let i = 0; i <= text.length - windowSize; i += stepSize) {
    const window = text.slice(i, i + windowSize);
    const entropy = shannonEntropy(window);

    if (entropy >= entropyThreshold && !inAnomaly) {
      // Start of anomalous region
      inAnomaly = true;
      anomalyStart = i;
    } else if (entropy < entropyThreshold && inAnomaly) {
      // End of anomalous region
      inAnomaly = false;
      const anomalyText = text.slice(anomalyStart, i + windowSize);
      const anomalyEntropy = shannonEntropy(anomalyText);
      const result = classifyContent(anomalyText);

      anomalies.push({
        offset: anomalyStart,
        length: anomalyText.length,
        entropy: anomalyEntropy,
        classification: result.classification,
        text:
          anomalyText.length > 200
            ? anomalyText.slice(0, 100) + "..." + anomalyText.slice(-100)
            : anomalyText,
        confidence: result.confidence,
      });
    }
  }

  // Handle anomaly that extends to end of text
  if (inAnomaly) {
    const anomalyText = text.slice(anomalyStart);
    const anomalyEntropy = shannonEntropy(anomalyText);
    const result = classifyContent(anomalyText);
    anomalies.push({
      offset: anomalyStart,
      length: anomalyText.length,
      entropy: anomalyEntropy,
      classification: result.classification,
      text:
        anomalyText.length > 200
          ? anomalyText.slice(0, 100) + "..." + anomalyText.slice(-100)
          : anomalyText,
      confidence: result.confidence,
    });
  }

  return anomalies;
}

// --- Character class counting helpers ---

function countPrintable(text: string): number {
  let count = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c >= 0x20 && c <= 0x7e) count++;
  }
  return count;
}

function countAlphaNum(text: string): number {
  let count = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (
      (c >= 0x30 && c <= 0x39) || // 0-9
      (c >= 0x41 && c <= 0x5a) || // A-Z
      (c >= 0x61 && c <= 0x7a)    // a-z
    )
      count++;
  }
  return count;
}

function countBase64Chars(text: string): number {
  let count = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (
      (c >= 0x30 && c <= 0x39) || // 0-9
      (c >= 0x41 && c <= 0x5a) || // A-Z
      (c >= 0x61 && c <= 0x7a) || // a-z
      c === 0x2b || // +
      c === 0x2f || // /
      c === 0x3d    // =
    )
      count++;
  }
  return count;
}

function countHexChars(text: string): number {
  let count = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (
      (c >= 0x30 && c <= 0x39) || // 0-9
      (c >= 0x41 && c <= 0x46) || // A-F
      (c >= 0x61 && c <= 0x66)    // a-f
    )
      count++;
  }
  return count;
}
