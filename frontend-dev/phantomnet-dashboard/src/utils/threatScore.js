/**
 * Canonical Threat Score Normalization Utility
 * ============================================
 * Provides authoritative normalization, severity classification, and display
 * formatting aligned with PhantomNet's canonical ML thresholds (ML-2 / ML-3):
 * 
 * Thresholds:
 *   CRITICAL : score >= 0.80
 *   HIGH     : score >= 0.60 && score < 0.80
 *   MEDIUM   : score >= 0.40 && score < 0.60
 *   LOW      : score < 0.40
 * 
 * Rules:
 *   - Normalized internal representation is strictly 0.0 to 1.0.
 *   - Automatically detects and rescales legacy 0-100 inputs.
 *   - Preserves mathematical precision for logic while generating integer/formatted percentages for display.
 */

export const THREAT_THRESHOLDS = {
  CRITICAL: 0.80,
  HIGH: 0.60,
  MEDIUM: 0.40,
  LOW: 0.0,
};

/**
 * Normalizes any threat score input into canonical format.
 * 
 * @param {number|string|null|undefined} rawScore - Score input (0.0-1.0 or 0-100)
 * @returns {{
 *   normalized: number,
 *   percentage: number,
 *   percentageStr: string,
 *   severity: "CRITICAL"|"HIGH"|"MEDIUM"|"LOW",
 *   severityClass: string,
 *   isValid: boolean
 * }}
 */
export function normalizeThreatScore(rawScore) {
  if (rawScore === null || rawScore === undefined || rawScore === "") {
    return {
      normalized: 0.0,
      percentage: 0,
      percentageStr: "0%",
      severity: "LOW",
      severityClass: "threat-low",
      isValid: false,
    };
  }

  const num = typeof rawScore === "number" ? rawScore : parseFloat(rawScore);

  if (isNaN(num)) {
    return {
      normalized: 0.0,
      percentage: 0,
      percentageStr: "0%",
      severity: "LOW",
      severityClass: "threat-low",
      isValid: false,
    };
  }

  // Detect scale: if > 1.0, it's on a 0-100 scale
  let normalized = num;
  if (num > 1.0) {
    normalized = Math.min(1.0, num / 100);
  } else if (num < 0) {
    normalized = 0.0;
  }

  // Clamp to [0.0, 1.0]
  normalized = Math.max(0.0, Math.min(1.0, normalized));

  // Integer percentage (0-100)
  const percentage = Math.round(normalized * 100);
  const percentageStr = `${percentage}%`;

  // Canonical severity mapping
  let severity = "LOW";
  let severityClass = "threat-low";

  if (normalized >= THREAT_THRESHOLDS.CRITICAL) {
    severity = "CRITICAL";
    severityClass = "threat-critical";
  } else if (normalized >= THREAT_THRESHOLDS.HIGH) {
    severity = "HIGH";
    severityClass = "threat-high";
  } else if (normalized >= THREAT_THRESHOLDS.MEDIUM) {
    severity = "MEDIUM";
    severityClass = "threat-medium";
  }

  return {
    normalized,
    percentage,
    percentageStr,
    severity,
    severityClass,
    isValid: true,
  };
}

/**
 * Maps threat score to CSS color hex.
 */
export function getThreatColor(normalizedScore) {
  const norm = normalizeThreatScore(normalizedScore).normalized;
  if (norm >= 0.80) return "#ff0055"; // Critical Red/Pink
  if (norm >= 0.60) return "#f77f00"; // High Orange
  if (norm >= 0.40) return "#fcbf49"; // Medium Yellow
  return "#00ff41";                   // Low Green
}
