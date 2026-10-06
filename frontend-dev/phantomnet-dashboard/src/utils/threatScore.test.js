/* global process */
/**
 * Automated test suite for Threat Score Normalization Utility
 * Validates canonical ML thresholds and boundary values:
 * 0.00, 0.39, 0.40, 0.59, 0.60, 0.79, 0.80, 1.00
 */
import { normalizeThreatScore, getThreatColor } from './threatScore.js';

let passed = 0;
let failed = 0;

function assertEqual(actual, expected, message) {
  if (actual === expected) {
    passed++;
  } else {
    failed++;
    console.error(`❌ FAIL: ${message} | Expected: ${expected}, Got: ${actual}`);
  }
}

console.log('--- Testing Canonical Threat Score Normalization ---');

// Boundary test: 0.00 (LOW)
const s0 = normalizeThreatScore(0.00);
assertEqual(s0.normalized, 0.0, '0.00 normalized');
assertEqual(s0.percentage, 0, '0.00 percentage');
assertEqual(s0.severity, 'LOW', '0.00 severity');
assertEqual(s0.severityClass, 'threat-low', '0.00 class');

// Boundary test: 0.39 (LOW)
const s39 = normalizeThreatScore(0.39);
assertEqual(s39.normalized, 0.39, '0.39 normalized');
assertEqual(s39.percentage, 39, '0.39 percentage');
assertEqual(s39.severity, 'LOW', '0.39 severity');

// Boundary test: 0.40 (MEDIUM)
const s40 = normalizeThreatScore(0.40);
assertEqual(s40.normalized, 0.40, '0.40 normalized');
assertEqual(s40.percentage, 40, '0.40 percentage');
assertEqual(s40.severity, 'MEDIUM', '0.40 severity');
assertEqual(s40.severityClass, 'threat-medium', '0.40 class');

// Boundary test: 0.59 (MEDIUM)
const s59 = normalizeThreatScore(0.59);
assertEqual(s59.normalized, 0.59, '0.59 normalized');
assertEqual(s59.percentage, 59, '0.59 percentage');
assertEqual(s59.severity, 'MEDIUM', '0.59 severity');

// Boundary test: 0.60 (HIGH)
const s60 = normalizeThreatScore(0.60);
assertEqual(s60.normalized, 0.60, '0.60 normalized');
assertEqual(s60.percentage, 60, '0.60 percentage');
assertEqual(s60.severity, 'HIGH', '0.60 severity');
assertEqual(s60.severityClass, 'threat-high', '0.60 class');

// Boundary test: 0.79 (HIGH)
const s79 = normalizeThreatScore(0.79);
assertEqual(s79.normalized, 0.79, '0.79 normalized');
assertEqual(s79.percentage, 79, '0.79 percentage');
assertEqual(s79.severity, 'HIGH', '0.79 severity');

// Boundary test: 0.80 (CRITICAL)
const s80 = normalizeThreatScore(0.80);
assertEqual(s80.normalized, 0.80, '0.80 normalized');
assertEqual(s80.percentage, 80, '0.80 percentage');
assertEqual(s80.severity, 'CRITICAL', '0.80 severity');
assertEqual(s80.severityClass, 'threat-critical', '0.80 class');

// Boundary test: 1.00 (CRITICAL)
const s100 = normalizeThreatScore(1.00);
assertEqual(s100.normalized, 1.00, '1.00 normalized');
assertEqual(s100.percentage, 100, '1.00 percentage');
assertEqual(s100.severity, 'CRITICAL', '1.00 severity');

// Legacy 0-100 rescale tests
const legacyMedium = normalizeThreatScore(46);
assertEqual(legacyMedium.normalized, 0.46, 'Legacy 46 normalized to 0.46');
assertEqual(legacyMedium.percentage, 46, 'Legacy 46 percentage');
assertEqual(legacyMedium.severity, 'MEDIUM', 'Legacy 46 severity');

const legacyCritical = normalizeThreatScore(92);
assertEqual(legacyCritical.normalized, 0.92, 'Legacy 92 normalized to 0.92');
assertEqual(legacyCritical.percentage, 92, 'Legacy 92 percentage');
assertEqual(legacyCritical.severity, 'CRITICAL', 'Legacy 92 severity');

// Edge cases & null handling
const nullScore = normalizeThreatScore(null);
assertEqual(nullScore.isValid, false, 'null is marked invalid');
assertEqual(nullScore.percentage, 0, 'null defaults to 0%');
assertEqual(nullScore.severity, 'LOW', 'null defaults to LOW');

const undefScore = normalizeThreatScore(undefined);
assertEqual(undefScore.isValid, false, 'undefined is marked invalid');

// Color mapping
assertEqual(getThreatColor(0.92), '#ff0055', 'Critical color');
assertEqual(getThreatColor(0.70), '#f77f00', 'High color');
assertEqual(getThreatColor(0.45), '#fcbf49', 'Medium color');
assertEqual(getThreatColor(0.20), '#00ff41', 'Low color');

console.log(`\nResults: ${passed} assertions passed, ${failed} failed.`);
if (failed > 0) {
  process.exit(1);
} else {
  console.log('✅ ALL THREAT SCORE NORMALIZATION TESTS PASSED.');
}
