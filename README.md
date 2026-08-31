<div align="center">

# 🛡️ PhantomNet V3
### Autonomous AI Deception Grid, Threat Intelligence & Active Incident Response Platform

*A production-grade cybersecurity platform deploying containerized deceptive services, detecting complex multi-stage attack campaigns with machine learning, and autonomously synthesizing MITRE ATT&CK-mapped threat intelligence, Snort/Sigma IDS rules, Jinja2/LLM incident response playbooks, and STIX 2.1 / TAXII 2.1 feeds.*

<p align="center">
  <img src="https://img.shields.io/badge/version-v3.0.0-00ff41?style=for-the-badge&logo=github&logoColor=white" alt="Version" />
  <img src="https://img.shields.io/badge/build-passing-brightgreen?style=for-the-badge&logo=githubactions&logoColor=white" alt="Build" />
  <img src="https://img.shields.io/badge/tests-94%25_coverage-success?style=for-the-badge&logo=pytest&logoColor=white" alt="Coverage" />
  <img src="https://img.shields.io/badge/license-MIT-009688?style=for-the-badge&logo=opensourceinitiative&logoColor=white" alt="License" />
  <img src="https://img.shields.io/badge/MITRE_ATT%26CK-12_Techniques-FF6F00?style=for-the-badge" alt="MITRE ATT&CK" />
  <img src="https://img.shields.io/badge/STIX_2.1-OASIS_Compliant-7B1FA2?style=for-the-badge" alt="STIX 2.1" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/FastAPI-0.104+-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/React-19.2+-61DAFB?style=for-the-badge&logo=react&logoColor=black" alt="React" />
  <img src="https://img.shields.io/badge/PostgreSQL-15+-336791?style=for-the-badge&logo=postgresql&logoColor=white" alt="PostgreSQL" />
  <img src="https://img.shields.io/badge/Docker-Compose_v2-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker" />
  <img src="https://img.shields.io/badge/AI_Engine-Ollama_%2F_Mistral_7B-EA580C?style=for-the-badge&logo=openai&logoColor=white" alt="Ollama / Mistral" />
</p>

<p align="center">
  <a href="#-what-is-phantomnet">What is PhantomNet?</a> &bull;
  <a href="#-key-features--capabilities">Key Features</a> &bull;
  <a href="#-end-to-end-pipeline-architecture">Pipeline Architecture</a> &bull;
  <a href="#-sentinel-layer--mitre-attck-matrix">Sentinel Intelligence Layer</a> &bull;
  <a href="#-soc-dashboard--analyst-workflows">SOC Dashboard & Workflows</a> &bull;
  <a href="#-tech-stack">Tech Stack</a> &bull;
  <a href="#-quick-start--docker-deployment">Quick Start & Docker</a> &bull;
  <a href="#-environment-configuration">Configuration</a> &bull;
  <a href="#-api-reference">API Reference</a> &bull;
  <a href="#-project-structure">Project Structure</a> &bull;
  <a href="#-team">Team</a>
</p>

</div>

---

## 📌 What is PhantomNet?

Traditional Intrusion Detection and Prevention Systems (IDS/IPS) are fundamentally reactive: they analyze traffic after an intrusion occurs, rely on lagging signatures, and generate overwhelming volumes of noisy alerts. Standalone honeypots solve part of this problem by offering zero-false-positive deception, but historically lack automated intelligence generation, machine learning correlation, and active response workflows.

**PhantomNet V3** bridges this gap. It is an **autonomous active cyber defense platform** that couples containerized multi-protocol deception with a real-time machine learning threat engine, a deterministic MITRE ATT&CK mapping core, automated Snort/Sigma rule synthesis, Jinja2/LLM-enhanced incident playbooks, and standardized STIX 2.1 / TAXII 2.1 threat sharing.

```
┌─────────────────┐     ┌──────────────────┐     ┌───────────────────┐     ┌───────────────────┐
│ Multi-Protocol  │ ──► │  23D ML Threat   │ ──► │  Sentinel Layer   │ ──► │ Active Response   │
│ Deception Grid  │     │ Anomaly Scoring  │     │ MITRE ATT&CK Map  │     │ Playbooks & Rules │
│ SSH/HTTP/FTP/SMTP     │ IF + RF + LSTM   │     │ Snort / Sigma / AI│     │ TAXII 2.1 / SOC   │
└─────────────────┘     └──────────────────┘     └───────────────────┘     └───────────────────┘
```

### Architectural Differentiation

| Capability | Traditional Honeypots | Legacy PhantomNet (V1/V2) | **PhantomNet V3 (Current)** |
| :--- | :--- | :--- | :--- |
| **Service Emulation** | Single protocol (SSH or HTTP) | Isolated SSH + HTTP traps | **Multi-Protocol Mesh (SSH, HTTP, FTP, SMTP) with write-only data diode** |
| **Threat Detection** | Basic regex / string match | Single-model scoring (Random Forest) | **23D Feature Vector Ensemble (Isolation Forest + RF + LSTM Forecasting + SHAP XAI)** |
| **Campaign Correlation** | None (discrete log lines) | Basic IP aggregation | **DBSCAN Campaign Clustering across multi-IP temporal attack sessions** |
| **Tactical Context** | Generic alert categories | Static attack classification | **Dynamic 12-Technique MITRE ATT&CK Mapping across 8 Tactical Matrix Categories** |
| **Rule Generation** | Manual analyst engineering | Basic Snort string alerts | **Autonomous Snort 2.9/3.0 + Sigma YAML Rule Synthesis with classtypes & SIDs** |
| **Response Automation** | Static text templates | Basic markdown output | **Jinja2 + Ollama Mistral 7B Playbooks, 4-Signal Confidence Scoring, PDF/JSON Export** |
| **Threat Intel Sharing** | Raw CSV or Syslog | Static STIX JSON dump | **Live TAXII 2.1 Server with Collection Discovery, STIX 2.1 Bundles, and TLP Markings** |
| **Analyst Interface** | Command line / raw files | Read-only web UI | **React 19 NOC + Sentinel Console with Batch Approval Workflows & ATT&CK Heatmap** |

---

## 🚀 Key Features & Capabilities

### 🕸️ 1. Multi-Protocol Deception Grid
- **Interactive SSH Honeypot (`:2222`)**: Paramiko-based emulated shell recording credentials, keystroke timing, executed bash commands, downloaded payloads, and honeyfile interactions.
- **Vulnerable Web Services (`:8080`)**: Flask-based HTTP trap capturing Path Traversal, SQL Injection, Cross-Site Scripting (XSS), web shell uploads, scanner probes (Nikto/Nmap), and C2 registration attempts.
- **Deceptive FTP Service (`:2121`)**: Custom pyftpdlib daemon intercepting brute-force authentication, passive data transfer (`:30000-30020`), and dropped malware binaries.
- **Sinkhole SMTP Server (`:2525`)**: Asynchronous `aiosmtpd` trap logging phishing lures, spam campaigns, forged sender headers, and oversized multi-part payloads.
- **Isolation-First Architecture**: Honeypots execute within unprivileged containers (`--cap-drop=ALL`, `--security-opt=no-new-privileges`, read-only root filesystems) forwarding logs via a write-only API proxy.

### 🧠 2. Real-Time ML Detection & Explainable AI (XAI)
- **23-Dimensional Feature Vectorization**: Ingests raw packet flows and extracts statistical features (payload entropy, packet burst ratios, inter-arrival time variance, protocol flags, header-to-payload ratios).
- **Sub-15ms Ensemble Inference**: Serialized dual-pipeline combining unsupervised **Isolation Forest** (zero-day anomaly detection) and supervised **Random Forest** (threat pattern classification).
- **Temporal Volumetric Forecasting**: Deep **LSTM neural network** analyzing sliding time windows to forecast DDoS floods, brute-force escalations, and port scanning waves.
- **Explainable Predictions (SHAP)**: Calculates Shapley Additive exPlanations for every score, providing SOC analysts with exact feature weight attribution (e.g., *"Payload Entropy contributed +42% to CRITICAL classification"*).

### 🛡️ 3. Sentinel Autonomous Intelligence Core
- **12 MITRE ATT&CK Techniques**: Automatically maps attack signatures across 8 tactics (Reconnaissance, Initial Access, Execution, Persistence, Credential Access, Lateral Movement, Discovery, Exfiltration, Impact).
- **Production IDS Rule Synthesis**: Generates syntax-valid **Snort 2.9/3.0** rules (with flow tracking, mapped classtypes, severity priorities, and thread-safe SIDs) and **Sigma YAML** rules (with logsource definitions and ATT&CK tags).
- **Dynamic Incident Playbooks**: Renders contextual containment runbooks via Jinja2 templates, enriched with IOC tables, threat scores, containment steps, and escalation procedures.
- **AI Narrative Synthesis (Ollama & Mistral 7B)**: Integrates local LLM inference to generate executive summaries, tactical impact assessments, and technical timelines, backed by seamless offline template fallbacks.
- **4-Signal Confidence Scoring**: Evaluates campaign severity using cluster density, mean ML anomaly scores, IOC entropy, and multi-protocol indicators.

### 📡 4. Standardized Threat Sharing (STIX 2.1 / TAXII 2.1)
- **OASIS STIX 2.1 Compliance**: Generates JSON intelligence bundles containing `Identity`, `AttackPattern`, `Indicator`, `Relationship`, and `MarkingDefinition` (TLP:WHITE to TLP:RED) objects.
- **TAXII 2.1 Server**: RESTful threat feed discovery (`/taxii2/`), API Roots (`/taxii2/root/`), collections (`/taxii2/root/collections/{id}/objects/`), and STIX content negotiation (`application/taxii+json;version=2.1`).
- **SIEM & SOAR Integration**: Automated CEF/Syslog streaming for Splunk, Elastic/ELK, and enterprise security platforms.

### 📊 5. SOC Operations & Analyst Workbench
- **Real-Time NOC (React 19 + Vite)**: WebSocket-driven live event stream, interactive packet inspector, real-time threat counter metrics, and audio-visual alerting.
- **Interactive Sentinel Management**: Paginated and filterable playbook workspace with 1-click single and batch approval/rejection workflows, analyst attribution, and audit trail logging.
- **Visual Analytics**: Interactive MITRE ATT&CK Matrix heatmap, temporal campaign timeline progression charts, and multi-format export engines (PDF, Markdown, JSON, STIX 2.1).

---

## 🏗️ End-to-End Pipeline Architecture

The complete lifecycle from deceptive packet capture to distributed threat dissemination operates through seven tightly integrated stages:

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'primaryColor': '#0f172a', 'primaryTextColor': '#e2e8f0', 'primaryBorderColor': '#334155', 'lineColor': '#38bdf8', 'secondaryColor': '#1e293b', 'tertiaryColor': '#0f172a'}}}%%
graph TD
    classDef external fill:#7f1d1d,stroke:#ef4444,stroke-width:2px,color:#fff;
    classDef honeypot fill:#14532d,stroke:#22c55e,stroke-width:2px,color:#fff;
    classDef ingestion fill:#1e3a8a,stroke:#3b82f6,stroke-width:2px,color:#fff;
    classDef ml fill:#0369a1,stroke:#0ea5e9,stroke-width:2px,color:#fff;
    classDef sentinel fill:#581c87,stroke:#a855f7,stroke-width:2px,color:#fff;
    classDef ops fill:#1f2937,stroke:#64748b,stroke-width:2px,color:#fff;
    classDef sharing fill:#065f46,stroke:#10b981,stroke-width:2px,color:#fff;

    Attacker["🌐 Threat Actor / Scanner"]:::external -->|Port 2222| SSH["SSH Trap (Paramiko)"]:::honeypot
    Attacker -->|Port 8080| HTTP["HTTP Trap (Flask)"]:::honeypot
    Attacker -->|Port 2121| FTP["FTP Trap (pyftpdlib)"]:::honeypot
    Attacker -->|Port 2525| SMTP["SMTP Trap (aiosmtpd)"]:::honeypot

    subgraph TrapMesh ["Layer 1: Deception Grid (Isolated Containers)"]
        SSH
        HTTP
        FTP
        SMTP
    end

    TrapMesh -->|Write-Only REST Proxy| Diode["Data Diode & Ingestion"]:::ingestion
    Diode -->|Persist Logs| DB[(PostgreSQL 15)]:::ingestion

    subgraph IntelligenceEngine ["Layer 2: ML Inference & Correlation"]
        DB -->|Batch Poll & Stream| Analyzer["Threat Analyzer"]:::ml
        Analyzer <-->|23D Vector Extraction| MLEnsemble["ML Pipeline\n(Isolation Forest + RF + LSTM)"]:::ml
        MLEnsemble -->|Threat Score + SHAP XAI| Analyzer
        Analyzer -->|Threshold Trigger Score >= 85| DBSCAN["Campaign Clustering (DBSCAN)"]:::ml
    end

    subgraph SentinelPipeline ["Layer 3: Sentinel Autonomous Threat Core"]
        DBSCAN -->|Campaign Clusters| SentinelSvc["Sentinel Service"]:::sentinel
        SentinelSvc --> Mitre["MITRE ATT&CK Mapper\n(12 Techniques / 8 Tactics)"]:::sentinel
        Mitre --> RuleGen["IDS Rule Generator\n(Snort 2.9/3.0 + Sigma YAML)"]:::sentinel
        Mitre --> STIXGen["STIX 2.1 Builder\n(Indicators + Patterns + TLP)"]:::sentinel
        Mitre --> PBGen["Playbook Generator\n(Jinja2 Engine)"]:::sentinel
        PBGen <-->|Optional Narrative Context| LLM["Ollama / Mistral 7B\n(AI Narrative Engine)"]:::sentinel
        SentinelSvc --> Scorer["4-Signal Confidence Scorer\n(CRITICAL / HIGH / MED / LOW)"]:::sentinel
        
        RuleGen --> SentinelDB[(Sentinel DB)]:::ingestion
        STIXGen --> SentinelDB
        PBGen --> SentinelDB
        Scorer --> SentinelDB
    end

    subgraph SOCWorkbench ["Layer 4: Operations, Presentation & Dissemination"]
        API["FastAPI REST & WebSocket Core"]:::ops
        SentinelDB <-->|REST API| API
        API <-->|WebSocket Stream| Dashboard["React 19 NOC Dashboard"]:::ops
        API <-->|REST State Management| SentinelUI["Sentinel Management Console"]:::ops
        SentinelUI -->|Analyst Approval / Reject| API
        API -->|STIX 2.1 Collection Queries| TAXII["TAXII 2.1 Feed Server"]:::sharing
        API -->|CEF / Syslog Stream| SIEM["External SIEM / SOAR (Splunk/ELK)"]:::sharing
        API -->|SMTP Notifications| EmailAlerts["Email Alert Engine"]:::sharing
    end
```

### End-to-End Threat Processing Sequence

1. **Adversary Engagement**: Attacker probes honeypot services (e.g., automated credential brute-force on port 2222 or SQLi payload against port 8080).
2. **Telemetry Ingestion**: The honeypot traps commands, headers, hashes, and session metadata, forwarding events via an unprivileged write-only proxy into PostgreSQL 15.
3. **23D Feature Vectorization & ML Scoring**: The `ThreatAnalyzer` extracts 23 behavioral features and evaluates them through the Isolation Forest + Random Forest ensemble (sub-15ms inference).
4. **Campaign Clustering**: DBSCAN groups related multi-IP events occurring within spatial and temporal windows into structured attack campaigns.
5. **Sentinel ATT&CK Mapping**: The `MitreMapper` resolves the specific attack pattern into an official ATT&CK technique (e.g., `T1110.001` - Brute Force: Password Guessing).
6. **Automated Rule & Intelligence Synthesis**:
   - `RuleGenerator` builds production-ready Snort (flow-tracking, SIDs) and Sigma rules.
   - `STIXBuilder` packages standardized OASIS STIX 2.1 bundles with IOC indicators.
   - `PlaybookGenerator` renders Jinja2 incident response runbooks (optionally enhanced with Mistral 7B LLM narrative synthesis).
   - `ConfidenceScorer` computes composite severity across cluster size, ML scores, IOC density, and multi-protocol factors.
7. **SOC Review & Threat Sharing**: Alerts and playbooks populate the React 19 Sentinel Dashboard. Analysts perform one-click approvals, export rules in ZIP/PDF/JSON/STIX format, or stream intelligence live via TAXII 2.1 collections and SIEM loggers.

---

## 🛡️ Sentinel Layer & MITRE ATT&CK Matrix

The Sentinel Layer is PhantomNet's automated cyber threat intelligence (CTI) engine, transforming raw trap detections into structured, actionable enterprise defense artifacts.

### 🎯 MITRE ATT&CK Technique Mapping Matrix

PhantomNet maps 12 distinct attack signatures across 8 ATT&CK tactics:

| Attack Signature | ATT&CK ID | Technique Name | Tactic | Default Severity | Target Protocol |
| :--- | :---: | :--- | :--- | :---: | :---: |
| `SSH_AUTH_FAILURE` | **T1110.001** | Password Guessing | Credential Access | `HIGH` | SSH (:2222) |
| `SSH_HIGH_ACTIVITY` | **T1021.004** | SSH Lateral Movement | Lateral Movement | `MEDIUM` | SSH (:2222) |
| `HTTP_SQL_INJECTION` | **T1190** | Exploit Public-Facing App | Initial Access | `CRITICAL` | HTTP (:8080) |
| `HTTP_XSS_ATTEMPT` | **T1059.007** | JavaScript Interpreter | Execution | `HIGH` | HTTP (:8080) |
| `HTTP_PATH_TRAVERSAL` | **T1083** | File & Directory Discovery | Discovery | `HIGH` | HTTP (:8080) |
| `HTTP_SCANNER_BEHAVIOR` | **T1046** | Network Service Discovery | Discovery | `MEDIUM` | HTTP (:8080) |
| `FTP_DATA_EXFILTRATION` | **T1048.003** | Exfiltration Over Non-C2 | Exfiltration | `CRITICAL` | FTP (:2121) |
| `SMTP_LARGE_PAYLOAD` | **T1071.003** | Mail Protocol C2 | Command and Control | `HIGH` | SMTP (:2525) |
| `DISTRIBUTED_BRUTE_FORCE` | **T1110.004** | Credential Stuffing | Credential Access | `CRITICAL` | Multi-IP SSH/HTTP |
| `LOW_AND_SLOW_SCAN` | **T1595.001** | Active IP Block Scanning | Reconnaissance | `MEDIUM` | All Protocols |
| `MULTI_PROTOCOL_ATTACK` | **T1046** | Network Service Scanning | Discovery | `HIGH` | Multi-Port Mesh |
| `HIGH_FREQUENCY_ATTACK` | **T1498** | Network Denial of Service | Impact | `CRITICAL` | All Protocols |

### 📐 4-Signal Confidence Scoring Model

Every generated playbook is evaluated against a 4-signal weighted confidence algorithm:

$$\text{Confidence} = 0.35 \times S_{\text{cluster}} + 0.35 \times S_{\text{ML}} + 0.20 \times S_{\text{IOC}} + 0.10 \times S_{\text{protocol}}$$

| Signal Dimension | Weight | Mathematical Formulation / Evaluation |
| :--- | :---: | :--- |
| **Cluster Volume ($S_{\text{cluster}}$)** | **35%** | Scaled logarithmically based on the total number of correlated events in the DBSCAN cluster. |
| **ML Threat Score ($S_{\text{ML}}$)** | **35%** | Mean normalized anomaly score ($\mu$) from the Isolation Forest + Random Forest ensemble. |
| **IOC Density ($S_{\text{IOC}}$)** | **20%** | Ratio of unique indicator IPs/hashes relative to total connection attempts. |
| **Multi-Protocol Factor ($S_{\text{protocol}}$)** | **10%** | Multiplier bonus applied when attacks span multiple honeypot vectors (e.g., SSH + HTTP). |

- **Severity Thresholds**: `CRITICAL` ($\ge 0.80$) • `HIGH` ($\ge 0.60$) • `MEDIUM` ($\ge 0.40$) • `LOW` ($< 0.40$)

### 📝 Auto-Generated Detection Formats

#### 1. Snort 2.9 / 3.0 Rules
- Includes bidirectional flow tracking (`flow:to_server,established`), mapped classtypes, severity priorities, MITRE external URLs, and thread-safe sequential SIDs ($1000001+$):
```snort
alert tcp any any -> $HOME_NET 2222 (msg:"PHANTOMNET [T1110.001] SSH Brute Force Campaign Detected"; flow:to_server,established; threshold:type both,track by_src,count 5,seconds 60; classtype:attempted-admin; priority:1; reference:url,attack.mitre.org/techniques/T1110/001; sid:1000142; rev:1;)
```

#### 2. Sigma YAML Rules
- Standardized YAML detection definitions compatible with Splunk, Elastic, Sentinel, and QRadar converters:
```yaml
title: PhantomNet - SQL Injection Exploit Attempt (T1190)
id: 7f3b892a-4c21-419b-98f3-8b7a912e4310
status: production
description: Auto-generated detection for SQL Injection against HTTP honeypot
author: PhantomNet Sentinel Autonomous Core
references:
  - https://attack.mitre.org/techniques/T1190/
logsource:
  category: webserver
  service: http
detection:
  selection:
    c-uri|contains:
      - "UNION SELECT"
      - "' OR 1=1"
      - "INFORMATION_SCHEMA"
  condition: selection
level: critical
tags:
  - attack.initial_access
  - attack.t1190
```

#### 3. OASIS STIX 2.1 & TAXII 2.1
- Produces complete STIX 2.1 JSON bundles linked with `Identity`, `AttackPattern`, `Indicator`, and `Relationship` objects. Bundles are queried directly by external TAXII 2.1 clients (e.g., `taxii2-client`):
```json
{
  "type": "bundle",
  "id": "bundle--3b89419a-9e12-4c28-98f1-28147d3910ab",
  "objects": [
    {
      "type": "identity",
      "id": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
      "name": "PhantomNet Autonomous Sentinel Core",
      "identity_class": "system"
    },
    {
      "type": "attack-pattern",
      "id": "attack-pattern--8a129ef3-412e-48a1-9b93-84192bda9112",
      "name": "Brute Force: Password Guessing",
      "external_references": [
        { "source_name": "mitre-attack", "external_id": "T1110.001" }
      ]
    }
  ]
}
```

---

## 💻 SOC Dashboard & Analyst Workflows

The React 19 Sentinel Dashboard provides an enterprise-ready command center for SOC analysts:

### 1. Operations Overview & Live Telemetry
Real-time monitoring of all active honeypot nodes, live incoming attack telemetry, threat level breakdown, and system health status.

![SOC Operations Dashboard](docs/images/dashboard.png)

---

### 2. Sentinel Playbook Workspace & Real-Time Metrics
Centralized queue of auto-generated incident playbooks with aggregate status metrics (Pending, Approved, Rejected, Average Confidence):

| Main Playbook Queue | Pipeline Metric Widgets |
| :--- | :--- |
| ![Sentinel Playbook Workspace](docs/screenshots/sentinel_dashboard.png) | ![Pipeline Statistics](docs/screenshots/sentinel_stats_widgets.png) |

---

### 3. Playbook Inspection, Rule Previews & Multi-Format Exports
Analysts inspect rendered Markdown playbooks, AI narratives, and generated detection rules across tabbed preview interfaces:

| Incident Playbook Viewer | Snort Rule Preview Tab | Sigma YAML Preview Tab |
| :--- | :--- | :--- |
| ![Playbook Modal](docs/screenshots/sentinel_playbook_viewer.png) | ![Snort Preview](docs/screenshots/sentinel_rule_preview_snort.png) | ![Sigma Preview](docs/screenshots/sentinel_rule_preview_sigma.png) |

---

### 4. Human-in-the-Loop Approval Workflow
State-aware review transitions with immediate analyst attribution and real-time navigation notification updates:

| State: Pending Review (Before) | State: Approved & Disseminated (After) | Header Alert Notification |
| :--- | :--- | :--- |
| ![Pending State](docs/screenshots/sentinel_workflow_before.png) | ![Approved State](docs/screenshots/sentinel_workflow_after.png) | ![Nav Badge](docs/screenshots/sentinel_nav_badge.png) |

---

### 5. MITRE ATT&CK Matrix Heatmap & Campaign Timelines
Visual threat analytics displaying real-time technique coverage and temporal attack progression:

| Interactive ATT&CK Matrix Heatmap | Temporal Campaign Timeline |
| :--- | :--- |
| ![ATT&CK Heatmap](docs/images/mitre_matrix.png) | ![Campaign Timeline](docs/images/campaign_timeline.png) |

---

## 🛠️ Tech Stack

| Layer / Subsystem | Technology | Version | Architectural Purpose & Rationale |
| :--- | :--- | :--- | :--- |
| **Backend Framework** | [FastAPI](https://fastapi.tiangolo.com/) | `0.104+` | High-performance asynchronous REST API, WebSocket streams, and native OpenAPI validation. |
| **ASGI Web Server** | [Uvicorn](https://www.uvicorn.org/) | `0.24+` | Lightweight, high-throughput asynchronous server running uvloop. |
| **Primary Database** | [PostgreSQL](https://www.postgresql.org/) | `15-alpine` | Relational ACID storage, JSONB support for payload metadata, and complex joins for correlation. |
| **ORM & Migrations** | [SQLAlchemy](https://www.sqlalchemy.org/) / [Alembic](https://alembic.sqlalchemy.org/) | `2.0+` / `1.12+` | Declarative models, connection pooling, and automated schema migrations. |
| **ML Inference Core** | [Scikit-Learn](https://scikit-learn.org/) | `1.3+` | Serialized Isolation Forest anomaly detection and Random Forest multi-class classification. |
| **Neural Forecasting** | [TensorFlow / Keras](https://www.tensorflow.org/) | `2.14+` | Recurrent LSTM neural network for temporal traffic volume forecasting. |
| **Explainable AI (XAI)** | [SHAP](https://shap.readthedocs.io/) | `0.43+` | TreeExplainer calculating exact feature Shapley values for analyst transparency. |
| **AI / Local LLM** | [Ollama](https://ollama.ai/) / Mistral 7B | `Latest` | Local, air-gapped LLM inference for playbook narrative generation with zero external cloud dependencies. |
| **Frontend Framework** | [React](https://react.dev/) | `19.2+` | Component-based UI with modern React hooks, concurrent rendering, and real-time state management. |
| **Frontend Tooling** | [Vite](https://vitejs.dev/) | `5.0+` | Ultra-fast HMR and optimized production bundle compilation. |
| **Styling & Icons** | [TailwindCSS](https://tailwindcss.com/) / [Lucide](https://lucide.dev/) | `4.0+` / `0.29+` | Modern responsive dark/light cybersecurity design system and vector iconography. |
| **Data Visualization** | [Recharts](https://recharts.org/) | `2.10+` | Responsive SVG charts for campaign timelines, radar plots, and threat density curves. |
| **Protocol Emulation** | [Paramiko](https://www.paramiko.org/) / [pyftpdlib](https://github.com/giampaolo/pyftpdlib) / [aiosmtpd](https://aiosmtpd.readthedocs.io/) | `3.4+` / `1.5+` / `1.4+` | Authentic interactive SSH, FTP, and SMTP protocol handling and telemetry capture. |
| **Threat Standards** | [stix2](https://github.com/oasis-open/cti-python-stix2) / [PyYAML](https://pyyaml.org/) / [Jinja2](https://jinja.palletsprojects.com/) | `3.0+` / `6.0+` / `3.1+` | OASIS STIX 2.1 JSON packaging, Sigma rule serialization, and dynamic playbook rendering. |
| **Containerization** | [Docker](https://www.docker.com/) / Compose | `24.0+` / `v2.20+` | Isolated multi-container deployment with unprivileged capability dropping. |

---

## ⚡ Quick Start & Docker Deployment

### 📋 Prerequisites

- **Docker Engine**: `24.0+` & **Docker Compose**: `v2.0+`
- **Python**: `3.11+` *(for native local development)*
- **Node.js**: `18.0+` & `npm 9.0+` *(for frontend development)*
- **System Specifications**: Minimum 4 vCPU, 8GB RAM, 50GB Disk *(16GB RAM recommended if running local Ollama LLM)*

---

### 🐳 1. Production Docker Deployment (Recommended)

Clone the repository, configure your environment variables, and launch the complete stack:

```bash
# 1. Clone the PhantomNet repository
git clone https://github.com/sriram21-09/PhantomNet.git
cd PhantomNet

# 2. Copy the environment configuration template
cp .env.example .env

# 3. Secure your environment variables
# Ensure you set strong credentials for POSTGRES_PASSWORD, JWT_SECRET, and API_KEY
nano .env

# 4. Build and deploy all production containers in detached mode
docker-compose -f docker-compose.prod.yml build --no-cache
docker-compose -f docker-compose.prod.yml up -d

# 5. Verify system health
curl -s http://localhost:8000/api/v1/system/health | jq
```

#### Exposed Service Ports in Production

| Container Service | Host Port | Protocol / Purpose |
| :--- | :--- | :--- |
| **React Frontend** | `http://localhost:80` (or `:3000` in dev) | Web Application & Sentinel Dashboard |
| **FastAPI Core API** | `http://localhost:8000` | REST API, OpenAPI Docs (`/docs`), WebSocket Stream |
| **SSH Honeypot** | `localhost:2222` | Emulated SSH Terminal Trap |
| **HTTP Honeypot** | `http://localhost:8080` | Emulated Web Application Trap |
| **FTP Honeypot** | `localhost:2121` (`:30000-30020`) | Emulated FTP Data & Auth Trap |
| **SMTP Honeypot** | `localhost:2525` | Emulated Mail Sinkhole Trap |
| **Ollama LLM Engine** | `http://localhost:11434` | Local AI Narrative Inference Container |

---

### 💻 2. Local Development Setup (Native Mode)

If you prefer to run services natively on your host machine for development:

#### A. Backend API & Intelligence Core
```bash
cd backend
python -m venv .venv

# On Linux / macOS:
source .venv/bin/activate
# On Windows PowerShell:
# .\.venv\Scripts\Activate.ps1

# Install backend dependencies
pip install -r requirements.txt

# Run database migrations
alembic upgrade head

# Start FastAPI development server with live reload
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

#### B. React Frontend Application
```bash
cd frontend-dev/phantomnet-dashboard

# Install frontend dependencies
npm install

# Start Vite development server
npm run dev
# Accessible at http://localhost:5173
```

#### C. Optional Local Ollama AI Setup
```bash
# Pull and start Mistral 7B model locally
ollama run mistral
```

---

### 🧪 3. Data Seeding & Attack Simulation

To populate the database with realistic sample attack telemetry or execute live multi-vector attack simulations against your running honeypots:

```bash
# Populate database with historical baseline attacks and pre-computed playbooks
python populate_db.py

# Simulate live multi-vector attacks against running honeypots (SSH, HTTP, FTP)
python scripts/simulate_attacker.py --target localhost --rate aggressive

# Test email alerting engine configuration
python scripts/send_test_email.py --recipient soc-analyst@example.com
```

---

## ⚙️ Environment Configuration

All system configurations are managed through `.env`. Below is a comprehensive reference of available variables:

| Category | Environment Variable | Default Value | Description / Usage |
| :--- | :--- | :--- | :--- |
| **Database** | `DATABASE_URL` | `postgresql://postgres:postgres@localhost:5432/phantomnet` | Full database connection string (PostgreSQL or SQLite fallback). |
| | `DB_HOST` / `DB_PORT` | `postgres` / `5432` | PostgreSQL server hostname and listening port. |
| | `POSTGRES_USER` | `postgres` | PostgreSQL root username. |
| | `POSTGRES_PASSWORD` | `postgres` | Strong database password (change in production). |
| | `POSTGRES_DB` | `phantomnet` | Database schema name. |
| **API Core** | `API_HOST` / `API_PORT` | `0.0.0.0` / `8000` | FastAPI network binding interface and listening port. |
| | `ENVIRONMENT` | `production` | Environment profile (`development`, `staging`, `production`). |
| | `JWT_SECRET` | `your-super-secret-jwt-key` | 64-character cryptographic key for JWT signature validation. |
| | `JWT_EXPIRY_DAYS` | `7` | Access token expiration lifetime in days. |
| | `API_KEY` | `pn_live_secret_key` | Master programmatic API key for external SIEM/SOAR ingestion. |
| **Sentinel Core** | `SENTINEL_ENABLED` | `true` | Toggles automatic Sentinel playbook synthesis upon campaign trigger. |
| | `SENTINEL_AUTO_GEN_ENABLED` | `false` | Enables APScheduler background periodic generation cycles. |
| | `SENTINEL_AUTO_GEN_INTERVAL_MINUTES`| `30` | Interval in minutes between automated playbook generation runs. |
| **Local AI Engine** | `SENTINEL_LLM_ENABLED` | `false` | Enables AI-enhanced narrative generation inside incident playbooks. |
| | `SENTINEL_LLM_HOST` | `http://ollama:11434` | HTTP endpoint for the Ollama inference container. |
| | `SENTINEL_LLM_MODEL` | `mistral` | Local LLM model tag (`mistral`, `gemma:2b`, etc.). |
| **Email Alerts** | `SENTINEL_EMAIL_ALERTS_ENABLED` | `false` | Toggles automated SMTP alerts for critical incident playbooks. |
| | `SENTINEL_EMAIL_SMTP_HOST` | `smtp.gmail.com` | Outgoing SMTP mail server hostname. |
| | `SENTINEL_EMAIL_SMTP_PORT` | `587` | Outgoing SMTP mail server port (587 for TLS, 465 for SSL). |
| | `SENTINEL_EMAIL_SEVERITY_THRESHOLD`| `CRITICAL` | Minimum severity triggering email dispatches (`CRITICAL`, `HIGH`, `MEDIUM`). |
| **Threat Intel** | `ABUSE_IPDB_KEY` | *(optional)* | AbuseIPDB API key for automatic external IP reputation lookup. |
| | `ALIENVAULT_OTX_KEY` | *(optional)* | AlienVault OTX API key for threat pulse correlation. |

---

## 📡 API Reference & Integration

PhantomNet provides a fully documented REST API with OpenAPI/Swagger specifications at `http://localhost:8000/docs`.

### Key Sentinel & Threat Intelligence Endpoints

| Method | Endpoint Route | Description & Parameters |
| :--- | :--- | :--- |
| `GET` | `/api/sentinel/playbooks` | List playbooks with pagination (`limit`, `offset`), `status`, `tactic`, and `search`. |
| `GET` | `/api/sentinel/playbooks/{id}` | Retrieve complete playbook details including rendered Markdown and rule metadata. |
| `GET` | `/api/sentinel/stats` | Pipeline statistics (total playbooks, approved count, pending review, average confidence). |
| `GET` | `/api/sentinel/mitre/matrix` | Aggregated ATT&CK matrix heatmap with technique coverage and event counts. |
| `POST` | `/api/sentinel/generate` | Trigger manual playbook generation for specific IP/event clusters. |
| `PATCH` | `/api/sentinel/playbooks/{id}/approve` | Approve a pending playbook (attaches analyst ID and review timestamp). |
| `PATCH` | `/api/sentinel/playbooks/{id}/reject` | Reject a pending playbook with audit reason logging. |
| `POST` | `/api/sentinel/playbooks/batch/approve`| Batch approve an array of playbook IDs. |
| `POST` | `/api/sentinel/playbooks/{id}/export` | Export playbook in requested format (`format=md`, `json`, `stix`, `pdf`). |
| `GET` | `/api/sentinel/rules/snort` | List all synthesized Snort 2.9/3.0 rules. |
| `GET` | `/api/sentinel/rules/sigma` | List all synthesized Sigma YAML rules. |
| `GET` | `/taxii2/` | TAXII 2.1 Server Discovery endpoint. |
| `GET` | `/taxii2/root/collections/{id}/objects/` | Query STIX 2.1 threat intelligence objects via TAXII 2.1 feed collections. |

### CLI Integration Examples (`curl`)

```bash
# 1. Inspect System Health
curl -s http://localhost:8000/api/v1/system/health | jq

# 2. Query Sentinel Pipeline Statistics
curl -s -H "Authorization: Bearer pn_live_secret_key" \
     http://localhost:8000/api/sentinel/stats | jq

# 3. Manually Trigger Sentinel Playbook Generation for a Suspicious Campaign
curl -X POST "http://localhost:8000/api/sentinel/generate" \
     -H "Authorization: Bearer pn_live_secret_key" \
     -H "Content-Type: application/json" \
     -d '{
       "source_ips": ["185.220.101.5"],
       "target_ports": [2222],
       "protocols": ["TCP"],
       "event_count": 120
     }' | jq

# 4. Export Playbook as a Standalone STIX 2.1 Bundle
curl -X POST "http://localhost:8000/api/sentinel/playbooks/1/export?format=stix" \
     -H "Authorization: Bearer pn_live_secret_key" -o playbook_1_stix.json

# 5. Query the Live TAXII 2.1 Threat Collection
curl -s -H "Accept: application/taxii+json;version=2.1" \
     http://localhost:8000/taxii2/root/collections/default/objects/ | jq
```

---

## 📁 Project Structure

```text
PhantomNet/
├── backend/                             # FastAPI Backend & Intelligence Services
│   ├── api/                             # REST & WebSocket API Controllers
│   │   ├── sentinel.py                  # Sentinel Layer REST API (16 endpoints)
│   │   ├── taxii.py                     # TAXII 2.1 Threat Sharing Server
│   │   ├── threat.py                    # Threat Analysis & Scoring Routes
│   │   ├── analytics.py                 # Campaign & Metric Analytics
│   │   └── websocket.py                 # Real-Time WebSocket Streaming Hub
│   ├── database/                        # Database Connection & SQLAlchemy Models
│   │   ├── database.py                  # Engine & Session Management
│   │   └── models.py                    # PostgreSQL Tables (Events, Clusters, Logs)
│   ├── honeypots/                       # Honeypot Service Implementations
│   │   ├── ssh/                         # Paramiko Interactive Shell Trap (:2222)
│   │   ├── http/                        # Flask Web Application Trap (:8080)
│   │   ├── ftp/                         # pyftpdlib Data & Malware Trap (:2121)
│   │   └── smtp/                        # aiosmtpd Phishing Sinkhole (:2525)
│   ├── ml_engine/                       # ML Detection & Explainability Pipelines
│   │   ├── feature_extractor.py         # 23D Feature Vectorization
│   │   ├── isolation_forest.py          # Anomaly Detection Inference
│   │   ├── random_forest.py             # Supervised Threat Classification
│   │   ├── lstm_forecaster.py           # Temporal Volume Prediction
│   │   └── shap_explainer.py            # SHAP Feature Attribution Logic
│   ├── sentinel/                        # Autonomous Threat Intelligence Subsystem
│   │   ├── mitre_mapper.py              # 12 ATT&CK Technique Mapping Engine
│   │   ├── rule_generator.py            # Snort & Sigma IDS Rule Synthesizer
│   │   ├── playbook_generator.py        # Jinja2 Response Playbook Builder
│   │   ├── llm_service.py               # Ollama / Mistral 7B AI Narrative Engine
│   │   ├── stix_enhanced.py             # OASIS STIX 2.1 Bundle Serializer
│   │   ├── confidence_scoring.py        # 4-Signal Confidence Scoring Algorithm
│   │   ├── email_alerts.py              # Outgoing SMTP Alert Notification Service
│   │   ├── models.py                    # SentinelPlaybook & AuditLog ORM Schemas
│   │   └── templates/                   # Jinja2 Markdown & YAML Templates
│   ├── tests/                           # Comprehensive Pytest Suites (94%+ coverage)
│   └── main.py                          # ASGI Entrypoint & Router Assembly
├── frontend-dev/phantomnet-dashboard/   # Modern React 19 Frontend
│   ├── src/
│   │   ├── components/                  # UI Components (NOC Feed, Charts, Modals)
│   │   │   └── sentinel/                # PlaybookViewer, RulePreview, ApprovalControls
│   │   ├── pages/                       # View Pages (SentinelDashboard, Overview, Analytics)
│   │   └── services/                    # Axios API Clients & WebSocket Connectors
│   └── package.json                     # Frontend Dependencies & Scripts
├── docs/                                # Technical Architecture & Developer Guides
│   ├── system_architecture.md           # System Architecture & Design Philosophy
│   ├── ml_pipeline.md                   # ML Pipeline & Model Training Specifications
│   ├── rule_generation.md               # Snort/Sigma Rule Generation Deep-Dive
│   ├── playbook_templates.md            # Jinja2 Playbook Authoring Guide
│   ├── llm_integration.md               # Ollama Mistral LLM Integration Guide
│   ├── taxii_interoperability.md        # STIX 2.1 & TAXII 2.1 Threat Sharing Spec
│   ├── production_deployment_guide.md   # Enterprise Production Hardening & Ops
│   └── DOCKER_GUIDE.md                  # Comprehensive Docker Compose Manual
├── ml_models/                           # Serialized ML Model Artifacts (Git LFS)
├── scripts/                             # Utility & Testing Automation Scripts
│   ├── simulate_attacker.py             # Multi-Protocol Attack Generator
│   ├── send_test_email.py               # SMTP Alert Validator
│   └── clear_db.py                      # Database Cleanup Utility
├── docker-compose.yml                   # Base Multi-Container Configuration
├── docker-compose.prod.yml              # Production Hardened Docker Compose Overrides
├── populate_db.py                       # Historical Seed & Demonstration Ingestion
├── requirements.txt                     # Backend Dependencies
└── README.md                            # Main Documentation & Overview
```

---

## 🔒 Security Architecture & Hardening

PhantomNet is built from the ground up on defense-in-depth principles to protect the host infrastructure while exposing realistic attack surfaces:

- **Unprivileged Container Isolation**: All honeypot services execute with dropped Linux capabilities (`--cap-drop=ALL`), non-root users, disabled privilege escalation (`--security-opt=no-new-privileges`), and read-only container root filesystems.
- **Write-Only Data Diode Architecture**: Honeypot containers possess zero read access to backend databases or internal network segments. Logs and session metadata are strictly forwarded across an isolated internal bridge via write-only API proxies.
- **Strict Input Validation & Rate Limiting**: All API endpoints enforce strict Pydantic v2 schemas and token-bucket rate limiting to mitigate denial-of-service attempts.
- **Local AI Privacy Assurance**: The integrated Ollama LLM runs completely offline within a local container, ensuring sensitive incident context, attacker telemetry, and internal network IP addresses are never transmitted to external cloud providers.
- **Role-Based Access Control (RBAC)**: Enforces granular JWT-authenticated roles: `Admin` (full system configuration), `Analyst` (playbook review, approve/reject, exports), and `Viewer` (read-only telemetry).

---

## 🗺️ Project Roadmap & Milestone Progression

```
[Month 1: Foundation] ──► [Month 2: ML Core] ──► [Month 3: Clustering] ──► [Month 4: Sentinel] ──► [Month 5: Scaling] ──► [Month 6: Production V3]
  Honeypot Grid             IF + RF + LSTM        DBSCAN Campaigns        MITRE Mapping + Rules   TAXII + LLM AI         Hardening + Release
```

| Phase | Milestone | Core Deliverables & Achievements | Status |
| :---: | :--- | :--- | :---: |
| **Month 1** | Foundation & Deception Grid | Multi-protocol honeypots (SSH, HTTP, FTP, SMTP), PostgreSQL schema, FastAPI backend, React NOC dashboard. | ✅ Complete |
| **Month 2** | ML Threat Detection | 23D feature extraction, Isolation Forest + Random Forest ensemble, LSTM traffic forecasting, SHAP XAI tooltips. | ✅ Complete |
| **Month 3** | Campaign Clustering & SIEM | DBSCAN multi-IP campaign correlation, CEF/Syslog streaming exporter, Splunk / ELK integrations. | ✅ Complete |
| **Month 4** | Sentinel Intelligence Layer | 12 MITRE ATT&CK mappings, automated Snort/Sigma rule synthesis, Jinja2 playbooks, 4-signal scoring, Sentinel UI. | ✅ Complete |
| **Month 5** | Advanced Intel & AI Enhancement | Local Ollama Mistral 7B LLM narrative synthesis, OASIS STIX 2.1 export, live TAXII 2.1 feed server, batch workflows. | ✅ Complete |
| **Month 6** | Production Hardening & Delivery | Complete E2E regression verification, Cypress UI tests, PDF streaming exports, enterprise documentation, V3.0.0 Release. | ✅ Complete |

---

## 📚 Technical Documentation Index

For in-depth technical documentation, refer to the dedicated guides in the `docs/` repository:

- 🏛️ **[System Architecture & Design Guide](docs/system_architecture.md)** — Architectural layers, data diode design, and threading models.
- 🧠 **[Machine Learning & Inference Pipeline](docs/ml_pipeline.md)** — Feature definitions, model hyperparameters, and SHAP mathematical formulation.
- 🤖 **[LLM Integration & AI Playbooks](docs/llm_integration.md)** — Ollama setup, Mistral prompt templates, few-shot conditioning, and fallback logic.
- 📜 **[IDS Rule Generation Specifications](docs/rule_generation.md)** — Snort 2.9/3.0 syntax, Sigma YAML structures, and classtype dictionaries.
- 📋 **[Incident Playbook Templates Guide](docs/playbook_templates.md)** — Jinja2 template inheritance, context variables, and runbook authoring.
- 📡 **[TAXII 2.1 & STIX Threat Sharing](docs/taxii_interoperability.md)** — TAXII collection endpoints, STIX 2.1 schemas, and external client setup.
- 🚀 **[Production Deployment & Hardening Guide](docs/production_deployment_guide.md)** — Enterprise deployment runbooks, monitoring, and secrets rotation.
- 🐳 **[Docker Compose Operations Guide](docs/DOCKER_GUIDE.md)** — Multi-container orchestration, port mappings, and healthchecks.
- 📖 **[API Documentation & Endpoint Reference](docs/api_documentation_v2.md)** — Complete OpenAPI REST and WebSocket endpoint specifications.
- 🤝 **[Contribution Guidelines](docs/CONTRIBUTING.md)** & **[Security Policy](SECURITY.md)** — Code conventions and vulnerability disclosure policy.

---

## 👥 Engineering Team

PhantomNet was developed as an advanced cybersecurity engineering platform by a team of four:

| Name | Role | Core Engineering Focus | GitHub Profile |
| :--- | :--- | :--- | :--- |
| **Kasukurthi Sriram** | **Team Lead & Security Architect** | System Architecture, Sentinel Autonomous Pipeline, ATT&CK Mapping & STIX/TAXII Core | [@sriram21-09](https://github.com/sriram21-09) |
| **Muramreddy Vivekananda Reddy** | **Security & Infrastructure Engineer** | Container Deception Grid, Protocol Emulation, Security Hardening & IDS Rules | [@VivekanandaReddy2006](https://github.com/VivekanandaReddy2006) |
| **Nattala Vikranth Chakravarthi** | **AI/ML & Threat Intelligence Engineer** | ML Ensemble Pipeline, Feature Extraction, LSTM Forecasting & LLM Reasoning | [@vikranthN101](https://github.com/vikranthN101) |
| **Satti Sai Ram Manideep Reddy** | **Frontend & UI/UX Engineer** | React 19 NOC Dashboard, Sentinel Management Console, WebSockets & Visual Analytics | [@sairammanideepreddy2123](https://github.com/sairammanideepreddy2123) |

---

<div align="center">
  <img src="https://img.shields.io/badge/License-MIT-009688?style=for-the-badge&logo=opensourceinitiative&logoColor=white" alt="License" />
  <p><b>PhantomNet Active Cyber Defense Platform</b> &bull; Copyright &copy; 2026 PhantomNet Engineering Team</p>
  <i>"Turn your network into an intelligent, autonomous weapon against the adversary."</i>
</div>
