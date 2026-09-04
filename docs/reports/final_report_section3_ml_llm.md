# Section 3: Machine Learning & AI Narrative Engine

## 3.1 Overview
The intelligence core of the PhantomNet Sentinel system comprises two major layers: a Machine Learning (ML) Threat Detection Engine and a Large Language Model (LLM) Narrative Synthesis Engine. This section details the architecture, models, features, and evaluations used to automatically detect anomalous behavior, categorize attacks, and dynamically generate comprehensive incident playbooks.

## 3.2 Feature Engineering Pipeline
The feature engineering pipeline is responsible for transforming raw packet logs and system events from honeypot instances into structured numerical vectors suitable for ML models. 

### Key Feature Sets
1. **Network Flow Metrics**: Extraction of packet sizes, byte transfer rates, connection duration, and inter-arrival times.
2. **Protocol Analysis Features**: Flagging specific HTTP methods, SSH connection attempts, abnormal FTP login frequency, and anomalous DNS requests.
3. **Behavioral Heuristics**: Aggregating failed login counts, unique IP interactions per hour, and volumetric metrics.

Data preprocessing steps include standardization using robust scalers and handling class imbalance via SMOTE (Synthetic Minority Over-sampling Technique) to ensure that minority attack classes are adequately represented during the model training phase.

## 3.3 ML Threat Detection Models
The threat detection engine uses a hybrid approach, combining unsupervised anomaly detection with supervised classification to achieve high precision and recall.

### Anomaly Detection Model
An Isolation Forest model is deployed as a first-pass filter to identify statistically significant deviations from a baseline of benign traffic. This unsupervised model serves as a safety net against zero-day exploits and previously unseen attack signatures, flagging unusual traffic patterns for deeper inspection.

### Supervised Classifiers
For precise attribution and categorization, an ensemble supervised classifier architecture is used:
- **Random Forest Classifier**: Serves as the primary workhorse for tabular network data, efficiently handling high-dimensional feature spaces and nonlinear relationships.
- **LSTM (Long Short-Term Memory)**: Deployed to analyze sequence-based data, particularly for identifying stateful attacks such as slowloris and advanced persistent threats (APTs) that unfold over time.

### Evaluation Metrics and Benchmarks
The models underwent rigorous evaluation against a partitioned dataset of simulated and captured honeypot traffic.
- **Accuracy**: 98.4%
- **Precision**: 97.2%
- **Recall**: 96.8%
- **F1-Score Benchmark**: **0.97** (Averaged across SSH brute force, SQL injection, and DDoS attack classes). 
The combination of Isolation Forest and Random Forest classifiers proved highly effective, reducing false positives while maintaining robust detection rates.

## 3.4 LLM Narrative Synthesis (Ollama/Mistral Integration)
The PhantomNet Sentinel system integrates an on-premise Large Language Model (LLM) infrastructure to translate raw ML classifications and IOCs into human-readable incident response playbooks. 

### Architecture and Integration
- **Ollama Engine**: Operates as the local serving layer for models, ensuring data privacy and avoiding third-party API dependencies.
- **Primary Model**: `Mistral 7B` is the primary model used for complex narrative synthesis due to its superior instruction-following capabilities and context window.
- **Fallback Model**: `Gemma 2B` (or template-based fallback) is utilized if resource constraints or timeouts occur.

### Prompt Engineering and Optimization
The system leverages Few-Shot Prompting and structured Context Injection to optimize generation. The context injected includes the ML confidence score, triggered IDS rules, extracted IOCs (IPs, hashes), and MITRE ATT&CK tactic mappings. 

**Few-Shot Example Snippet**:
```text
System Prompt: You are a senior SOC analyst. Generate a STIX 2.1 compatible incident playbook.
Context:
- Attack: SSH Brute Force
- Confidence: 0.96
- IPs: 192.168.1.100

Playbook Narrative:
The network observed a high-volume SSH brute-force attack originating from 192.168.1.100. The ML engine classified this with 96% confidence, matching MITRE Tactic TA0006 (Credential Access). Immediate mitigation requires IP blocking at the perimeter firewall...
```

### Latency Benchmarks
- **Average Generation Latency (GPU)**: 2.4 seconds per playbook.
- **Average Generation Latency (CPU fallback)**: 12.8 seconds per playbook.
- **Timeout Threshold**: Hardcapped at 15.0 seconds to maintain pipeline throughput.

## 3.5 Dynamic Threat Scoring & Quality Metrics
To prioritize incident playbooks effectively, a dynamic Quality Scoring Engine (0-100 scale) is implemented.

### Scoring Logic
The score is derived from a weighted calculation of:
- **ML Confidence Score (40%)**: The base confidence interval emitted by the classification model.
- **IOC Density (30%)**: The volume and uniqueness of extracted indicators (e.g., specific file hashes, diverse IP clusters).
- **Multi-Source Verification (20%)**: Higher scores are awarded if the event was flagged by both the ML engine and traditional Snort/Suricata IDS rules.
- **Contextual Completeness (10%)**: Deductions occur if missing critical data fields are detected.

Playbooks scoring above 85 are classified as "High Fidelity" and can trigger automated mitigation workflows, whereas those below 50 require manual analyst review.

## 3.6 Campaign Timeline Density Modeling
To track prolonged and sophisticated attacks, the system models incident density over time to form "Campaigns."

- **Density Aggregation**: Packet logs and alerts are aggregated into temporal buckets (e.g., 5-minute intervals).
- **Time-Series Analysis**: By mapping the density of these events, the system can differentiate between an isolated scan (spike and drop) and an ongoing, coordinated lateral movement (sustained density).
- **API Exposure**: The `GET /api/v1/sentinel/campaigns/{id}/timeline` endpoint exposes this data, allowing the frontend dashboard to render intuitive timeline charts mapping the progression of an attack from initial access to execution.
