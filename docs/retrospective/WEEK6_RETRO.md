# PhantomNet — Week 6 Retrospective

## Overview
Week 6 focused on stabilizing the ML-driven detection pipeline, validating feature extraction, ensuring low-latency inference, and preparing the system for scalable behavioral analysis in Week 7.

This week emphasized **verification, performance, and correctness** over adding new features.

---

## Goals Planned for Week 6
- Implement 15-feature extraction pipeline
- Integrate ML anomaly detection
- Add threat correlation logic
- Ensure live packet ingestion
- Validate latency and data freshness
- Prepare training dataset
- Stabilize backend services

---

## What Was Completed

### 1. Feature Extraction (15 Features)
- All 15 features successfully extracted per packet
- Verified via scripted tests on 30+ events
- Feature consistency validated between training and inference

**Status:** ✅ Complete

---

### 2. ML Anomaly Detection
- IsolationForest trained on 300 samples
- Model saved and reused during inference
- Prediction pipeline stable

**Status:** ✅ Complete

---

### 3. Threat Correlation Engine
- Combined ML anomaly score, rule-based signatures, and threat intel
- Deterministic verdict mapping (SAFE → WARNING → HIGH → CRITICAL)
- Integrated into live sniffer pipeline

**Status:** ✅ Complete

---

### 4. Performance Benchmarking
- ML inference latency benchmarked with 100+ runs
- Average latency: ~8–14 ms
- Well below 100 ms target

**Status:** ✅ Complete

---

### 5. Training Dataset
- 300 labeled packet logs generated
- Dataset exported to CSV
- Used for IsolationForest training

**Status:** ✅ Complete

---

### 6. Fresh Data Validation
- Real-time sniffer ingesting live traffic
- PostgreSQL `packet_logs` table verified (393k+ rows)
- API endpoints returning recent timestamps
- Dashboard reflects live data

**Status:** ✅ Complete

---

### 7. Backend API Stability
- `/analyze-traffic` functional
- `/api/events` filtering works as designed
- Invalid requests correctly rejected (422)

**Status:** ✅ Complete

---

## Issues Encountered & Resolutions

### Import Path Issues
- Root cause: mixed `backend.` vs relative imports
- Resolution: standardized runtime execution paths

### Feature Count Mismatch
- Root cause: model trained on outdated feature set
- Resolution: retrained model with correct 15-feature vector

### Database Environment Confusion
- SQLite used for local tests
- PostgreSQL confirmed as production DB

---

## What Did NOT Go Well
- Initial environment inconsistency between SQLite and PostgreSQL
- Frontend URL construction errors during manual testing

---

## Lessons Learned
- ML pipelines must lock feature schemas early
- Benchmarking should be automated earlier
- API validation errors are valuable indicators, not failures

---

## Final Status
**Week 6 is officially COMPLETE.**

All acceptance criteria met:
- Features verified
- Latency under threshold
- Training data exists
- Live data flowing
- APIs stable
- Code merged to `main`

---

## Next Week (Week 7 Preview)
Focus areas:
- Behavioral profiling
- Session-level aggregation
- Attack pattern learning
- Reduced false positives
- Dashboard intelligence upgrades
