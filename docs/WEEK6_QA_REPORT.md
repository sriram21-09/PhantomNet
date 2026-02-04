# WEEK 6 – QUALITY ASSURANCE (QA) REPORT

## Project: PhantomNet

## Phase: Week 6 – Day 5

---

## Objective

Perform final quality assurance and validation on PhantomNet to ensure feature extraction accuracy, data quality, and correct threat detection across all available honeypots before sign-off.

---

## Dataset Overview

* **Source File**: data/week6_test_events_balanced.csv
* **Total Events in Dataset**: 220
* **QA Sample Size**: 150 events (for data quality checks)
* **Honeypots Covered**:

  * SSH
  * HTTP
  * FTP
  * SMTP

Note: SSH logs were generated earlier but were not present in the original 220-event sample due to sampling limits. A balanced dataset was later created to include all honeypot types.

---

## Task-wise QA Results

### Task 1 – Feature Extraction Test (150 Events)

* Feature extraction executed successfully on all sampled events
* No crashes or exceptions observed

**Result**: PASS

---

### Task 2 – Feature Value Correctness

Validated the following:

* Honeypot values belong to expected set (ssh, http, ftp, smtp)
* Event values are non-empty strings
* Payload length values are valid non-negative integers
* Source IP presence correctly represented as boolean

**Result**: PASS

---

### Task 3 – Null or Corrupted Data Check

* Verified absence of null values in critical fields
* No corrupted or malformed rows detected

**Result**: PASS

---

### Task 4 – Data Quality Validation

* Total rows tested: 150
* Valid rows: 150
* Data quality percentage: 100%

Acceptance threshold (≥ 99%) satisfied.

**Result**: PASS

---

### Task 5 – Threat Detection Coverage (All Honeypots)

Threat indicators were validated across all honeypots present in the dataset:

* FTP: Reconnaissance activity detected
* SMTP: Relay / spoof indicators detected
* HTTP: SQL injection attempts detected
* SSH: Included in balanced dataset

**Result**: PASS

---

### Task 6 – SSH Brute Force Detection

* SSH brute-force detection logic validated using balanced dataset
* Multiple login failure events observed

**Result**: PASS

---

### Task 7 – HTTP SQL Injection Detection

* SQL injection attempts successfully detected via event labels and payload patterns

**Result**: PASS

---

### Task 8 – FTP Reconnaissance Detection

* FTP command and connection-based reconnaissance activity detected

**Result**: PASS

---

### Task 9 – SMTP Relay / Spoof Detection

* SMTP commands such as EHLO, MAIL FROM, RCPT TO, and DATA detected
* Indicates relay / spoof attempt behavior

**Result**: PASS

---

## QA Summary

| Task | Description               | Status |
| ---- | ------------------------- | ------ |
| 1    | Feature extraction        | PASS   |
| 2    | Feature correctness       | PASS   |
| 3    | Null / corruption check   | PASS   |
| 4    | Data quality ≥ 99%        | PASS   |
| 5    | Threat detection coverage | PASS   |
| 6    | SSH brute-force detection | PASS   |
| 7    | HTTP SQL injection        | PASS   |
| 8    | FTP reconnaissance        | PASS   |
| 9    | SMTP relay / spoof        | PASS   |

---

## Final QA Sign-off

All quality assurance tests for Week 6 – Day 5 have passed successfully. The dataset is clean, feature extraction is correct, and threat detection coverage is verified across all honeypots. PhantomNet is approved to proceed to the next phase.

**QA Status**: APPROVED
