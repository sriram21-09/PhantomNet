# PhantomNet Backend ML Integration & Runtime Forensic Audit

**Document:** Backend ML Runtime Forensic Audit (`BACKEND_ML_INTEGRATION_AUDIT.md`)  
**Auditor:** Lead ML & Reproducibility Auditor  
**Date:** 2026-10-01  
**Project:** PhantomNet  
**Status:** COMPLETE — REMEDIATION SPECIFIED  

---

## 1. Inventory of Backend ML Runtime Touchpoints

The machine learning subsystem interacts with the core FastAPI backend and persistent storage across multiple critical interfaces:

| Runtime Interface | Code Location | Mechanism / Trigger | Downstream Action | Forensic Status |
|---|---|---|---|---|
| **Synchronous Scoring API** | `backend/api/threat_scoring.py` (`POST /api/v1/analyze/threat-score`) | REST API request | Invokes `score_threat(ThreatInput)` | **MISALIGNED:** Feature slicing mismatch (`iloc[:, :12]`); unscaled inputs. |
| **Background Threat Worker** | `backend/services/threat_analyzer.py` | Polling loop (every 2s in daemon thread) | Scans `PacketLog` with `threat_level IS NULL`, batches to `score_threat_batch` | **DIVERGENT THRESHOLDS:** Overwrites threat levels using divergent thresholds; dummy LSTM score. |
| **Campaign Clustering Endpoint** | `backend/main.py` (`GET /api/v1/advanced/campaigns`) | REST API request | Calls `campaign_clusterer.identify_campaigns(hours_back)` | **UNSCALED COLLAPSE:** Returns 0 campaigns unless manual threshold injection occurs. |
| **Scheduled Clustering Worker** | `backend/services/scheduler_service.py` | Cron / Interval Scheduler | Runs `identify_campaigns` and triggers Sentinel playbook generation | **BLOCKED:** Halts downstream SOAR trigger when DBSCAN outputs 0 clusters. |
| **Explainability (XAI) Endpoint** | `backend/main.py` (`GET /api/v1/events/{id}/explanation`) | REST API request | Calls `explainer_service.explain_prediction(event_data)` | **PERMANENT 500 ERROR:** Crashes with `TypeError` in `_initialize()`. |
| **Incident Response Engine** | `backend/services/threat_analyzer.py:L388` | High / Critical threat trigger | Calls `response_executor.execute(...)` and `pcap_analyzer.start_capture(...)` | **UNRELIABLE:** Only triggers if ML score crosses mismatched thresholds. |

---

## 2. In-Depth Failure Mode Analysis

### 2.1 The Explainability Crash Bug (`TypeError: not iterable`)
- **Location:** `backend/ml_engine/explainability.py:L39-41`
- **Root Cause:**
  ```python
  model_components = load_model()
  if model_components and "model" in model_components:
      self.rf_model = model_components["model"]
  ```
  `model_loader.load_model()` returns a `RandomForestClassifier` instance (or `None`). It does **not** return a dictionary containing a `"model"` key.
  Executing `"model" in model_components` attempts to iterate over the `RandomForestClassifier`, raising:
  `TypeError: argument of type 'RandomForestClassifier' is not iterable`.
- **System Impact:** The explainer is never initialized. Any HTTP call to `/api/v1/events/{id}/explanation` returns `500 Internal Server Error: Failed to generate threat score explanation`.

### 2.2 Feature Extractor State Pollution in Asynchronous Loops
- **Location:** `backend/ml/feature_extractor.py:L48-80`
- **Root Cause:** `_FEATURE_EXTRACTOR` maintains internal state in `self.ip_events`, `self.ip_malicious_flags`, and `self.ip_destinations`.
- **Concurrency Defect:** `_FEATURE_EXTRACTOR` is a module-level singleton accessed simultaneously by:
  1. The FastAPI request-handling worker thread (`api/threat_scoring.py`).
  2. The background `ThreatAnalyzerService` thread (`services/threat_analyzer.py`).
  3. The `RealTimeSniffer` thread.
  None of the state-updating methods (`extract_features`) use locks (`threading.Lock` or `threading.RLock`). Concurrent mutations of `defaultdict(list)` lead to race conditions, inconsistent rolling rates, and corrupted memory under load.

### 2.3 Cascading Pipeline Halting (The DBSCAN Bottleneck)
- When a new attack campaign occurs:
  1. `PacketLog` records are ingested.
  2. `ThreatAnalyzerService` scores them. If scores fail to exceed `0.60` due to scrambled feature slicing, `is_malicious` remains `False`.
  3. `campaign_clusterer.identify_campaigns()` queries `is_malicious == True`. If no logs qualify, or if unscaled DBSCAN treats them as noise ($cluster = -1$), 0 campaigns are returned.
  4. `sentinel_service.generate_playbook()` is never invoked.
  5. MITRE ATT&CK mapping, Snort/Sigma rule generation, and STIX 2.1 bundling are never triggered.
- **Summary:** Upstream ML feature and scaling defects directly paralyze the entire downstream SOAR intelligence architecture.

---

## 3. Remediation Specifications for Backend ML Integration

1. **Fix `ModelExplainer` Initialization:**
   ```python
   model = load_model()
   if model is not None:
       self.rf_model = model
       self.explainer = shap.TreeExplainer(self.rf_model)
   ```
   Ensure the explainer passes standard, scaled 12D vectors matching the remediated model.
2. **Implement Thread-Safe Stateful Extraction:**
   - Add `threading.Lock()` to `FeatureExtractor` to protect sliding-window dictionaries during concurrent ingestion.
3. **Pipeline Coupling in Model Loading:**
   - `model_loader.load_model()` must return a complete scikit-learn `Pipeline` encapsulating both feature scaling and tree inference.
4. **End-to-End Autonomous Pipeline Integration:**
   - Remove manual database score injection from `tests/e2e/test_full_pipeline_e2e.py`.
   - Ensure the pipeline flows autonomously from raw socket packet ingestion $\to$ threat scoring $\to$ campaign clustering $\to$ playbook generation $\to$ STIX/rule export.
