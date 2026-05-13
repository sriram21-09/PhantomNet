<div align="center">

<img src="https://raw.githubusercontent.com/sriram21-09/PhantomNet/main/assets/phantomnet-banner.png" alt="PhantomNet Banner" width="100%" onerror="this.style.display='none'"/>

<br/>

<h1>🛡️ PhantomNet</h1>
<strong>The Ultimate Enterprise-Grade Distributed Deception & AI Threat Intelligence Platform</strong>

<p>
  <i>"Don't just log the adversary. Engage them, profile them, and neutralize them in real-time."</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Release-v2.0.1-00ff41?style=for-the-badge&logo=github&logoColor=white" alt="Version" />
  <img src="https://img.shields.io/badge/Build-Passing-brightgreen?style=for-the-badge&logo=githubactions&logoColor=white" alt="Build" />
  <img src="https://img.shields.io/badge/Coverage-94%25-success?style=for-the-badge&logo=codecov&logoColor=white" alt="Coverage" />
  <img src="https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker" />
  <img src="https://img.shields.io/badge/Kubernetes-Native-326CE5?style=for-the-badge&logo=kubernetes&logoColor=white" alt="Kubernetes" />
  <img src="https://img.shields.io/badge/License-MIT-009688?style=for-the-badge&logo=opensourceinitiative&logoColor=white" alt="License" />
</p>

<p align="center">
  <a href="#-executive-summary">Executive Summary</a> •
  <a href="#-system-architecture">Architecture</a> •
  <a href="#-the-deception-mesh">Deception Mesh</a> •
  <a href="#-aiml-threat-engine">AI/ML Engine</a> •
  <a href="#-technology-stack">Tech Stack</a> •
  <a href="#-repository-anatomy">Structure</a> •
  <a href="#-deployment--devops">Deployment</a> •
  <a href="#-configuration-reference">Config</a>
</p>

</div>

---

## 🎯 Executive Summary

**PhantomNet** is a production-ready, highly scalable deception framework engineered for modern zero-trust environments. Moving beyond legacy, passive honeypots, PhantomNet deploys a highly interactive, containerized mesh of protocol-specific traps. It ingests raw reconnaissance data, processes it through an embedded, multi-model AI pipeline, and automates infrastructure response—all within milliseconds.

Designed from the ground up for **Security Operations Centers (SOCs)** and **Enterprise Network Defenders**, it provides absolute visibility into lateral movement, zero-day exploitation attempts, and automated scanner behaviors, delivering actionable, zero-false-positive threat intelligence.

---

## 🏗️ System Architecture

PhantomNet is built on a decoupled, asynchronous microservices architecture, ensuring extreme resilience under heavy DDoS or credential-stuffing loads.

### Core Data Flow & Topology

```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'primaryColor': '#0f172a', 'primaryTextColor': '#e2e8f0', 'primaryBorderColor': '#334155', 'lineColor': '#3b82f6', 'secondaryColor': '#1e293b', 'tertiaryColor': '#0f172a'}}}%%
graph TD
    classDef external fill:#7f1d1d,stroke:#ef4444,stroke-width:2px,color:#fff;
    classDef honeypot fill:#14532d,stroke:#22c55e,stroke-width:2px,color:#fff;
    classDef core fill:#1e3a8a,stroke:#3b82f6,stroke-width:2px,color:#fff;
    classDef data fill:#3f3f46,stroke:#a1a1aa,stroke-width:2px,color:#fff;

    A[External Adversary / Malware]:::external -->|TCP/UDP/Application Payloads| DMZ
    
    subgraph DMZ ["🛡️ Deception Mesh (Containerized Traps)"]
        B(SSH Trap :2222):::honeypot
        C(HTTP Trap :8080):::honeypot
        D(FTP Trap :2121):::honeypot
        E(SMTP Sink :2525):::honeypot
    end

    DMZ -->|Asynchronous Event Stream| F[(PostgreSQL Core Database)]:::data
    
    subgraph Engine ["🧠 Intelligence & Orchestration Engine"]
        F -->|Batch Polling| G{Threat Analyzer}:::core
        G <-->|Feature Extraction| H[ML Pipeline <br/> IF + LSTM + DBSCAN]:::core
        H -->|Threat Score + SHAP| G
        G -->|Alert Generation| F
        G -->|Threshold Met| I[Correlation Engine]:::core
        I -->|Playbook Execution| J[Response Executor]:::core
    end
    
    J -.->|Automated Mitigation (e.g. IP Tables, Tarpit)| A
    
    subgraph Observability ["📊 SecOps & Telemetry"]
        K[FastAPI Gateway]:::core
        F <-->|REST APIs| K
        K <-->|WebSockets (Low Latency)| L[React 19 NOC Dashboard]:::core
        K -->|CEF / JSON Export| M[ELK / Splunk / SIEM]:::data
    end
```

---

## 🕸️ The Deception Mesh

PhantomNet deploys high-fidelity, interactive traps designed to fool both automated scanners and human operators. Each trap operates in a strict, isolated namespace.

<table width="100%">
<tr>
<td width="50%" valign="top">

### 🔒 SSH Emulator (Port 2222)
- **Engine:** Custom Python socket server mimicking OpenSSH.
- **Behavior:** Accepts weak credentials, drops attacker into a simulated Debian bash shell.
- **Telemetry Collected:** Usernames, passwords, full TTY command history, `wget`/`curl` payload URIs, malware hashes.

</td>
<td width="50%" valign="top">

### 🌐 Web App Trap (Port 8080)
- **Engine:** Flask-based dynamic response engine.
- **Behavior:** Mimics vulnerable CMS (WordPress/Tomcat). Simulates successful logins for known default credentials.
- **Telemetry Collected:** Full HTTP headers, User-Agents, SQL injection payloads, XSS attempts, Path traversal (`../../`) vectors.

</td>
</tr>
<tr>
<td width="50%" valign="top">

### 📁 FTP Sink (Port 2121)
- **Engine:** `pyftpdlib` with customized upload handling.
- **Behavior:** Allows anonymous logins and accepts file uploads, immediately sinking and hashing them for analysis.
- **Telemetry Collected:** Uploaded file hashes (MD5/SHA256), authentication sequences, `STOR`/`RETR` command frequency.

</td>
<td width="50%" valign="top">

### 📧 SMTP Relay (Port 2525)
- **Engine:** `aiosmtpd` sinkhole.
- **Behavior:** Acts as an open mail relay. Accepts emails but routes them to `/dev/null` after logging.
- **Telemetry Collected:** Sender IP/Domains, Phishing body templates, Malicious attachment signatures.

</td>
</tr>
</table>

---

## 🧠 AI/ML Threat Engine

PhantomNet does not rely on static signatures. It utilizes an advanced, multi-stage machine learning pipeline to detect novel, zero-day attack patterns.

1. **Feature Extraction:** Raw packet logs are transformed into a 23-dimensional continuous vector (entropy, payload length, connection frequency, GeoIP ASN risk, etc.).
2. **Isolation Forest (Anomaly Detection):** Rapidly scores the vector to identify statistical outliers against established baseline traffic.
3. **LSTM Sequence Forecasting:** Analyzes temporal connection patterns to predict volumetric attacks (e.g., impending DDoS or coordinated brute-force).
4. **DBSCAN Campaign Clustering:** Groups disparate alerts into coordinated "Attack Campaigns," attributing multiple IP addresses to a single threat actor.
5. **SHAP Explainability (XAI):** Generates feature-importance scores for every alert, providing security analysts with a human-readable explanation (e.g., *"Flagged 98% due to high payload entropy and anomalous geographic origin"*).

---

## 💻 Technology Stack

<div align="center">

| Domain | Core Technology | Supporting Libraries | Purpose |
| :--- | :--- | :--- | :--- |
| **Backend API** | **Python 3.11, FastAPI** | `Uvicorn`, `Pydantic v2`, `WebSockets` | High-concurrency REST/WS Gateway |
| **Data Layer** | **PostgreSQL 15** | `SQLAlchemy 2.0`, `Alembic` | ACID-compliant event storage & migrations |
| **Machine Learning** | **Scikit-Learn, TensorFlow** | `joblib`, `SHAP`, `MLflow` | Threat inference, XAI, model tracking |
| **Frontend NOC** | **React 19.2, Vite** | `TailwindCSS 4`, `Recharts`, `Zustand` | Low-latency, reactive SecOps dashboard |
| **Infrastructure** | **Docker, Docker-Compose** | `Alpine Linux`, `Traefik` | Containerization and reverse proxying |
| **Networking** | **Scapy, Socket** | `pyftpdlib`, `aiosmtpd` | Low-level packet manipulation & emulation |
| **Observability** | **Prometheus, Grafana** | `Logstash` (ELK) | System metrics and SIEM log exportation |

</div>

---

## 🗄️ Repository Anatomy

A deep dive into the engineering structure of the platform:

<details>
<summary><b>Click to expand the full repository structure</b></summary>

```text
PhantomNet/
├── backend/                     # Core Intelligence & Orchestration
│   ├── api/                     # REST & WebSocket Route Controllers
│   ├── core/                    # Dependency Injection, Security, Settings
│   ├── database/                # SQLAlchemy Models (PacketLog, Alert, IOC)
│   ├── ml_engine/               # ML Inference, SHAP Explainers, Clustering
│   ├── services/                # Background Workers (Analyzer, Correlation, SIEM)
│   ├── tests/                   # Pytest Suites (Unit, Integration, E2E)
│   └── main.py                  # ASGI Application Entrypoint
├── frontend-dev/                # React SecOps Dashboard
│   ├── src/
│   │   ├── components/          # Glass-morphism UI Widgets (Charts, Maps)
│   │   ├── pages/               # Views (Live Dashboard, Threat Hunting)
│   │   ├── services/            # Axios API Clients & Socket.io Handlers
│   │   └── hooks/               # Custom React Hooks
│   └── vite.config.ts           # Build configuration
├── honeypots/                   # Deception Mesh Traps
│   ├── ssh/                     # Python Socket Server (Port 2222)
│   ├── http/                    # Flask Vulnerability Simulator (Port 8080)
│   ├── ftp/                     # Pyftpdlib Sink (Port 2121)
│   └── smtp/                    # Aiosmtpd Relay (Port 2525)
├── ml_models/                   # Serialized ML Artifacts (.pkl, .h5)
├── playbooks/                   # Automated Response Logic
│   ├── brute_force.yaml         # Block/Tarpit rules for SSH/FTP
│   └── web_exploit.yaml         # WAF/Block rules for HTTP
├── docs/                        # Extensive Technical Documentation
├── docker-compose.yml           # Local Development Stack
├── docker-compose.prod.yml      # Hardened Production Stack
├── requirements.txt             # Pinned Backend Dependencies
└── .github/workflows/           # CI/CD (Lint, Test, Model Retrain, Build)
```
</details>

---

## 🚀 Deployment & DevOps

Designed for seamless transition from local development to global, distributed production environments.

### 1. Production Docker-Compose (Recommended)

Spins up the entire ecosystem in isolated Docker networks.

```bash
# Clone the enterprise repository
git clone https://github.com/sriram21-09/PhantomNet.git
cd PhantomNet

# Initialize configuration
cp .env.example .env
nano .env # Configure your secure keys (See Configuration Reference)

# Deploy the stack in detached mode
docker-compose -f docker-compose.prod.yml up -d --build

# Verify container health and logs
docker-compose ps
docker-compose logs -f backend
```

### 2. Kubernetes Operator Native (Phase 3 Roadmap)

PhantomNet is preparing for `Helm` and `Kustomize` deployments, allowing the honeypot mesh to auto-scale horizontally across clusters based on incoming threat volume.

### 3. Local Development (Source)

<details>
<summary><b>Expand for Local Python/Node setup</b></summary>

**Backend (FastAPI):**
```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

**Frontend (React/Vite):**
```bash
cd frontend-dev/phantomnet-dashboard
npm install
npm run dev
```
</details>

---

## ⚙️ Configuration Reference

PhantomNet relies on a strict `.env` file for secret management and behavioral tuning. 

| Variable | Type | Description | Default |
| :--- | :--- | :--- | :--- |
| `JWT_SECRET` | String | Cryptographic key for API and Dashboard auth | *Requires Generation* |
| `API_KEY` | String | Master key for programmatic log ingestion | *Requires Generation* |
| `POSTGRES_USER` | String | Database administrator username | `phantom_admin` |
| `POSTGRES_PASSWORD` | String | Database password | *Requires Generation* |
| `ENABLE_ELK_EXPORT` | Boolean | Toggles background CEF/JSON export to SIEM | `false` |
| `LOGSTASH_URL` | URI | Destination for SIEM exports | `http://logstash:5044` |
| `ML_BATCH_SIZE` | Integer | Number of logs to score per inference cycle | `500` |
| `AUTO_RESPONSE` | Boolean | Toggles execution of YAML playbooks | `true` |

---

## 🛡️ Security & Hardening Posture

Developing deception tech requires assuming the attacker will attempt to compromise the trap itself. PhantomNet implements defense-in-depth:

1. **Kernel-Level Dropping:** Honeypots are launched with `--security-opt=no-new-privileges` and `--cap-drop=ALL`.
2. **Read-Only Root:** Traps utilize read-only filesystems. Any filesystem writes (e.g., malware drops) go to ephemeral `tmpfs` mounts that vanish instantly upon container restart.
3. **Unidirectional Data Flow:** Honeypots push logs to the backend via a severely restricted internal API proxy. They possess zero database credentials and cannot query the backend.
4. **Pydantic Validation:** The FastAPI backend utilizes strict Pydantic v2 schemas. Malformed payloads are rejected at the edge with `422 Unprocessable Entity`, preventing deserialization attacks.
5. **Role-Based Access Control (RBAC):** JWTs enforce `ADMIN`, `ANALYST`, and `VIEWER` paradigms for API access.

---

## 🔌 API Reference & Programmability

PhantomNet operates API-first. Swagger UI is available at `/docs`.

### Example: Manual Playbook Execution

Manually trigger a defensive playbook via the REST API using an Admin token.

**Request:**
```bash
curl -X POST "https://api.phantomnet.local/v1/playbooks/trigger/brute_force" \
     -H "Authorization: Bearer <ADMIN_JWT_TOKEN>" \
     -H "Content-Type: application/json" \
     -d '{
           "target_ip": "185.150.12.4",
           "duration_minutes": 120,
           "action": "TARPIT"
         }'
```

**Response:**
```json
{
  "status": "success",
  "execution_id": "exec_88a91b",
  "applied_rules": ["iptables_drop", "tarpit_tcp_syn"],
  "timestamp": "2026-05-13T10:00:00Z"
}
```

---

## 🗺️ Engineering Roadmap

| Phase | Timeline | Strategic Objective | Status |
| :---: | :--- | :--- | :---: |
| **Phase I** | Q1-Q2 2026 | **MVP:** Multi-protocol honeypots, PostgreSQL integration, FastAPI architecture, React NOC Dashboard. | 🟢 **Delivered** |
| **Phase II** | Q3 2026 | **Intelligence:** ML Pipeline (IF, LSTM), WebSocket Streaming, Automated YAML Playbooks. | 🟢 **Delivered** |
| **Phase III** | Q4 2026 | **Scale:** Kubernetes Operator Native Scaling, ClickHouse integration for petabyte-scale telemetry, Multi-tenant RBAC. | 🟡 *In Progress* |
| **Phase IV** | Q1 2027 | **Advanced AI:** Reinforcement Learning for dynamic honeypot topology mutation, STIX/TAXII threat sharing federation. | ⚪ *Planned* |

---

## 🤝 Contributing & Community

PhantomNet is maintained by an elite core team but thrives on open-source collaboration. We welcome PRs from security researchers, ML engineers, and backend developers.

- **Contribution Guidelines:** Please read our [`CONTRIBUTING.md`](docs/CONTRIBUTING.md) for Git-flow standards, Conventional Commits, and code-style requirements.
- **Vulnerability Disclosure:** Do not open public issues for security flaws. Review our [`SECURITY.md`](SECURITY.md) for secure reporting channels.
- **CI/CD Requirements:** All PRs must pass GitHub Actions (Flake8, Black, Pytest, and Model validation) before review.

---

## 👨‍💻 Core Architecture Team

PhantomNet is engineered with precision by the Core Architecture Team:

| Architect | Focus Area | GitHub |
| :--- | :--- | :--- |
| **Kasukurthi Sriram** | Platform Architecture & Security Design | [@sriram21-09](https://github.com/sriram21-09) |
| **Muramreddy Vivekananda Reddy** | Container Orchestration & Protocol Emulation | [@VivekanandaReddy2006](https://github.com/VivekanandaReddy2006) |
| **Nattala Vikranth Chakravarthi** | ML Pipelines, Model Inference & XAI | [@Vikranth-tech](https://github.com/Vikranth-tech) |
| **Satti Sai Ram Manideep Reddy** | UI/UX, WebSocket Streaming & Frontend Architecture | [@sairammanideepreddy2123](https://github.com/sairammanideepreddy2123) |

<br/>

<div align="center">
  <img src="https://img.shields.io/badge/License-MIT-009688?style=for-the-badge&logo=opensourceinitiative&logoColor=white" alt="License" />
  <p>Copyright © 2026 PhantomNet Core Team</p>
  <i>"Turn your network into a weapon against the adversary."</i>
</div>