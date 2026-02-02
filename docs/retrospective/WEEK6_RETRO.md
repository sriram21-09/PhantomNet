# Week 6 Retrospective – PhantomNet
**Sprint:** Week 6  
**Role:** Team Lead  
**Focus:** ML Pipeline Integration, Threat Correlation, Stability  
**Duration:** Week 6 (Days 1–5)

---

## 1. Sprint Goal Summary

The primary objective of Week 6 was to complete the **end-to-end ML security pipeline** and ensure it is:

- Feature-complete (15 behavioral features)
- Fully integrated (sniffer → ML → correlation → DB → API)
- Stable on the `main` branch
- Ready for Week 7 expansion

This sprint focused more on **correctness, integration, and realism** rather than adding new features.

---

## 2. What Went Well ✅

### 2.1 End-to-End ML Pipeline Achieved
- Successfully integrated:
  - Feature extraction (15 features)
  - Anomaly detection (Isolation Forest)
  - Threat correlation (AI + rules + intel)
- Pipeline verified using scripted tests and live traffic.

### 2.2 Feature Engineering Stability
- All 15 features extract consistently.
- No null values or missing keys.
- Feature values behave logically over time (rates, variance, z-score).

### 2.3 Threat Correlation Logic Finalized
- Proper weighting implemented:
  - AI anomaly score
  - Signature-based detection
  - Threat intelligence feed
- Clear verdict mapping: `SAFE`, `WARNING`, `HIGH`, `CRITICAL`.

### 2.4 Main Branch Hygiene
- All critical code merged to `main`.
- Local artifacts cleaned and ignored.
- No broken imports or environment-specific paths remain.

### 2.5 Live System Validation
- Real-time sniffer successfully:
  - Captures traffic
  - Runs ML inference
  - Stores results in database
  - Serves data via API endpoints

---

## 3. What Did Not Go Well ❌

### 3.1 Import Path Inconsistencies
- Multiple issues due to mixed usage of:
  - `backend.ml.*`
  - `ml.*`
- Caused runtime failures under Uvicorn reload.
- Required several iterations to normalize imports.

### 3.2 Missing Performance Instrumentation
- Latency is architecturally low (<100 ms), but:
  - No explicit timing measurements were implemented.
- This limits objective performance validation.

### 3.3 Process Gaps
- Retrospective documentation was delayed until Day 5.
- Week 7 sprint issues not created during the sprint itself.

---

## 4. Key Technical Learnings 📌

1. **Package structure consistency is critical**  
   ML modules must be importable identically in:
   - Scripts
   - Uvicorn
   - CI environments

2. **Feature schema is a contract**  
   Any change to feature order or count directly affects ML models.

3. **Correlation logic must be explicit**  
   Clear separation of:
   - Detection
   - Risk scoring
   - Verdict classification

4. **Real-time systems reveal integration bugs early**  
   Live sniffing exposed issues that static tests did not.

---

## 5. Action Items for Week 7 🚀

| Item | Priority |
|----|----|
Add latency measurement middleware | High |
Freeze feature schema contract | High |
Improve threat correlation explainability | Medium |
Add ML confidence metadata to API | Medium |
Expand dataset with labeled attacks | Medium |
CI smoke test for ML imports | Medium |

---

## 6. Overall Sprint Verdict 🟢

**Sprint Outcome:** **SUCCESS**

Week 6 successfully delivered a **working, realistic, and extensible ML-driven defense pipeline**.  
While some process items lagged behind engineering execution, **no blocking technical debt remains**.

The system is stable, observable, and ready for **Week 7 expansion and hardening**.

---

**Prepared by:** Team Lead  
**Project:** PhantomNet  
**Date:** End of Week 6
