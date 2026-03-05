# Advanced Machine Learning Features

## 1. Unsupervised Anomaly Detection (Isolation Forest)
**Script**: `backend/ml_engine/unsupervised_detector.py`

### Theory & Operation
The core PhantomNet active-defense engine works on a supervised-learning assumption (Random Forest and LSTM Sequence mapping). To counterbalance zero-day threats outside the labeled training data, we integrated an Unsupervised `IsolationForest` detector.

Unsupervised models do not rely on labelled definitions of an "attack". Instead, it charts the baseline "normal" topography of traffic derived from the past 7 days of raw network events. New incoming packets that lie too far isolated statistically from this bulk cluster are automatically flagged as anomalies.

### Pipeline Integration
`threat_analyzer.py` utilizes an ensemble voting system. Currently, the isolation forest anomaly score (0.0 to 1.0 probability of outlier) acts as a `20%` deterministic weight factor shaping the final unified threat evaluation alongside the RF predicting logic.

---

## 2. Attack Campaign Clustering (DBSCAN)
**Script**: `backend/ml_engine/campaign_clustering.py`
**Endpoint**: `GET /api/v1/advanced/campaigns`

### Theory & Operation
Individual alerts isolated in a timeline lack context. By running DBSCAN (Density-Based Spatial Clustering of Applications with Noise), PhantomNet inherently identifies relationships across time and metadata linking disconnected alerts into structured, multi-stage "Campaigns" indicative of APTs (Advanced Persistent Threats) or broader network sweeps. 

### Data Yield
The DBSCAN algorithm parses inputs marked `MEDIUM` through `CRITICAL` over a specified lookback window (`hours_back=24`). The clustering maps arrays matching similar Source IPs, Target Ports, and sequential occurrence proximities.

---

## 3. Explainable AI (SHAP XAI)
**Script**: `backend/ml_engine/explainability.py`
**Endpoint**: `GET /api/v1/events/{id}/explanation`

### Theory & Operation
"Black-box" Neural Networks and Deep Decision trees are notoriously difficult to audit. To inject transparency into Random Forest outputs, we integrated **SHAP (SHapley Additive exPlanations)** mapping.
SHAP relies on game theory models to approximate the marginal contribution of *every single individual feature* involved in an evaluation node.

### Application
The API isolates specific scored packet objects and calculates feature significance. The endpoint output directly interprets the top contributing features (Negative or Positive weights) that directly influenced an attacker's threat score explicitly identifying what precisely triggered the engine into a specific verdict route.

---

## 4. Automated Retraining Pipeline (CI/CD Extension)
**Script**: `backend/ml_engine/retraining_pipeline.py`

### Theory & Operation
To prevent Model Drift decaying predictive accuracy as novel attacks restructure their approach, an automated `retrain_random_forest` pipeline targets historical events securely aggregated traversing the last `30 days` into fresh database slices automatically formatted utilizing `ml.feature_extractor.py`. 

### Logic Fallbacks
1. Extracts `30` days of logs locally.
2. Checks minimum class balance viability.
3. Spits and isolates testing sets before refitting new estimators (`n_estimators=50`).
4. Operates a fail-safe deployment check determining if `score > 0.85` F1 limits are successfully superseded before overwriting active `pkl` serialized models inside `ml_models/`. 
5. Caches legacy `.pkl` state parameters tracking metrics inside `ml_models/versions.json` logs ensuring viable roll-back environments.
